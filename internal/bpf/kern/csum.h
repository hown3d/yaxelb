#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static __always_inline __u16 csum_fold_helper(__u32 csum) {
  __u32 sum;
  sum = (csum >> 16) + (csum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

static __always_inline int tcp_csum(__sum16 old_csum, struct tcphdr *tcph_old,
                                    struct tcphdr *tcph) {
  __s64 csum =
      bpf_csum_diff((__be32 *)tcph_old, 4, (__be32 *)tcph, 4, ~old_csum);
  if (csum < 0) {
    return csum;
  }
  tcph->check = csum_fold_helper(csum);
  return 0;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
  iph->check = 0;
  unsigned long long csum =
      bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
  return csum_fold_helper(csum);
}
