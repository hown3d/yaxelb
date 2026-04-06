#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Helper to fold a 32-bit sum into a 16-bit one's complement checksum
static __always_inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (__u16)~csum;
}

static __always_inline __sum16 tcp_csum(struct tcphdr *tcph, struct iphdr *iph,
                                        __be32 old_saddr, __be32 old_daddr,
                                        __be16 old_sport, __be16 old_dport) {

  __u32 tcp_seed = (~tcph->check) & 0xFFFF;
  s64 tcp_diff = bpf_csum_diff(&old_saddr, 4, &iph->saddr, 4, tcp_seed);
  tcp_diff = bpf_csum_diff(&old_daddr, 4, &iph->daddr, 4, tcp_diff);

  if (old_sport != tcph->source || old_dport != tcph->dest) {

    // Group two 2-byte ports into exactly 4 bytes to satisfy bpf_csum_diff size
    // requirements
    struct {
      __be16 sport;
      __be16 dport;
    } old_ports = {old_sport, old_dport};

    struct {
      __be16 sport;
      __be16 dport;
    } new_ports = {tcph->source, tcph->dest};

    // Calculate diff on the grouped 4-byte variables safely
    tcp_diff = bpf_csum_diff((__be32 *)&old_ports, 4, (__be32 *)&new_ports, 4,
                             tcp_diff);
  }

  return csum_fold(tcp_diff);
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
  iph->check = 0;
  __u32 csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr),
                             iph->check);
  return csum_fold(csum);
}
