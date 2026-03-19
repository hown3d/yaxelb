#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
  __u32 check = iph->check;
  check += bpf_htons(0x0100);
  iph->check = (__u16)(check + (check >= 0xFFFF));
  return --iph->ttl;
}
