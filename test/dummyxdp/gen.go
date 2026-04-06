package dummyxdp

//go:generate  go tool bpf2go -cc clang-22 -tags linux dummy prog.c -- -I../../internal/bpf/kern/include/
