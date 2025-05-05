package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --cc clang --cflags "-O2 -g -Wall -I. -I/usr/include" --target bpfel pidhide bpf.c -- -v
