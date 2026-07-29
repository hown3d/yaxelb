#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

union v6addr {
  __u8 addr[16];
  struct {
    __u32 p1;
    __u32 p2;
    __u32 p3;
    __u32 p4;
  } p;
#define p1 p.p1
#define p2 p.p2
#define p3 p.p3
#define p4 p.p4
};

static __always_inline void ipv6_addr_copy(union v6addr *dst,
                                           const union v6addr *src) {
  __builtin_memcpy(dst, src, sizeof(*dst));
}
