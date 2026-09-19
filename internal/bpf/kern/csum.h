#pragma once

#include "helpers/ip6.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Helper to fold a 32-bit sum into a 16-bit one's complement checksum
static __always_inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static void csum_ports(s64 *diff, __be16 old_sport, __be16 old_dport,
                       __be16 new_sport, __be16 new_dport) {
  if (diff == NULL) {
    return;
  }

  if (old_sport != new_sport || old_dport != new_dport) {

    // Group two 2-byte ports into exactly 4 bytes to satisfy bpf_csum_diff size
    // requirements
    struct {
      __be16 sport;
      __be16 dport;
    } old_ports = {old_sport, old_dport};

    struct {
      __be16 sport;
      __be16 dport;
    } new_ports = {new_sport, new_dport};

    // Calculate diff on the grouped 4-byte variables safely
    *diff =
        bpf_csum_diff((__be32 *)&old_ports, 4, (__be32 *)&new_ports, 4, *diff);
  }
}

static __always_inline __sum16 l4_csum_v6(__sum16 check, struct ipv6hdr *iph,
                                          union v6addr *old_saddr,
                                          union v6addr *old_daddr,
                                          __be16 old_sport, __be16 old_dport,
                                          __be16 new_sport, __be16 new_dport) {

  __u32 seed = (~check) & 0xFFFF;
  s64 diff = bpf_csum_diff((__be32 *)old_saddr->addr, 16,
                           (__be32 *)iph->saddr.in6_u.u6_addr32, 16, seed);

  diff = bpf_csum_diff((__be32 *)old_daddr->addr, 16,
                       (__be32 *)iph->daddr.in6_u.u6_addr32, 16, diff);

  csum_ports(&diff, old_sport, old_dport, new_sport, new_dport);
  return csum_fold(diff);
}
static __always_inline __sum16 l4_csum_v4(__sum16 check, struct iphdr *iph,
                                          __be32 old_saddr, __be32 old_daddr,
                                          __be16 old_sport, __be16 old_dport,
                                          __be16 new_sport, __be16 new_dport) {

  __u32 seed = (~check) & 0xFFFF;
  s64 diff = bpf_csum_diff(&old_saddr, 4, &iph->saddr, 4, seed);
  diff = bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4, diff);

  csum_ports(&diff, old_sport, old_dport, new_sport, new_dport);
  return csum_fold(diff);
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
  iph->check = 0;
  __u32 csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr),
                             iph->check);
  return csum_fold(csum);
}
