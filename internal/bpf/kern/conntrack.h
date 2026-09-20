#pragma once

#include "bpf/bpf_endian.h"
#include "consts.h"
#include "helpers/ip6.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum conntrack_error {
  CONNTRACK_NOT_FOUND = 1,
  CONNTRACK_LOOKUP_ERROR = 2,
};

static __always_inline enum conntrack_error
lookup_kernel_conntrack(struct xdp_md *ctx, struct bpf_sock_tuple *tuple,
                        u32 tuple_sz, u8 proto) {
  // allocate here using declaration and assignment to not set fields to 0
  // which might be not available in older kernels. This ensures the loader
  // will not poision our call as the structures might mismatch.
  struct bpf_ct_opts ct_opts = {
      .netns_id = BPF_F_CURRENT_NETNS,
      .l4proto = proto,
  };

  // NF_BPF_CT_OPTS_SZ changed in
  // https://github.com/torvalds/linux/commit/ece4b296904167336d0aaab26bd7122018835202
  // (6.11) to 16 by adding support for zone awareness.
  struct nf_conn *ct =
      bpf_xdp_ct_lookup(ctx, tuple, tuple_sz, &ct_opts, sizeof(ct_opts));
  if (ct_opts.error != 0) {
    if (ct) {
      bpf_ct_release(ct);
    }
    if (ct_opts.error == -ENOENT)
      goto notfound;

    bpf_printk("errno of conntrack: %d", ct_opts.error);
    return -CONNTRACK_LOOKUP_ERROR;
  }

  if (ct) {
    bpf_ct_release(ct);
    // Connection exists, allow the packet
    return 0;
  } else {
  notfound:
    return -CONNTRACK_NOT_FOUND;
  }
}

static __always_inline enum conntrack_error
lookup_kernel_conntrack_v6(struct xdp_md *ctx, union v6addr *saddr,
                           __be16 sport, union v6addr *daddr, __be16 dport,
                           u8 proto) {
  struct bpf_sock_tuple tuple = {};
  ipv6_addr_copy((union v6addr *)&tuple.ipv6.saddr, saddr);
  ipv6_addr_copy((union v6addr *)&tuple.ipv6.daddr, daddr);
  tuple.ipv6.sport = sport;
  tuple.ipv6.dport = dport;

  bpf_printk("src %pI6:%d", tuple.ipv6.saddr, bpf_ntohs(tuple.ipv6.sport));
  bpf_printk("dst %pI6:%d", tuple.ipv6.daddr, bpf_ntohs(tuple.ipv6.dport));

  return lookup_kernel_conntrack(ctx, &tuple, sizeof(tuple.ipv6), proto);
}

static __always_inline enum conntrack_error
lookup_kernel_conntrack_v4(struct xdp_md *ctx, __be32 saddr, __be16 sport,
                           __be32 daddr, __be16 dport, u8 proto) {
  struct bpf_sock_tuple tuple = {};
  tuple.ipv4.saddr = saddr;
  tuple.ipv4.sport = sport;
  tuple.ipv4.daddr = daddr;
  tuple.ipv4.dport = dport;

  return lookup_kernel_conntrack(ctx, &tuple, sizeof(tuple.ipv4), proto);
}
