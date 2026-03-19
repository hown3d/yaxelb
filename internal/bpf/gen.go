package bpf

// `-type in_addr` adds in_addr c type as a explicit go type
//go:generate  go tool bpf2go -cc clang-22 -tags linux -type in_addr -type backend lb kern/lb.c -- -I./kern/include/
