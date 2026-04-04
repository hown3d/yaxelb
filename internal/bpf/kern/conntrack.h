#include "bpf/bpf_endian.h"
#include "consts.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static __always_inline int lookup_kernel_conntrack(struct xdp_md *ctx,
                                                   __be32 saddr, __be16 sport,
                                                   __be32 daddr, __be16 dport,
                                                   u8 proto) {
  struct bpf_sock_tuple tuple;
  tuple.ipv4.saddr = saddr;
  tuple.ipv4.sport = sport;
  tuple.ipv4.daddr = daddr;
  tuple.ipv4.dport = dport;
  struct bpf_ct_opts ct_opts = {.netns_id = BPF_F_CURRENT_NETNS,
                                .l4proto = proto};
  struct nf_conn *ct = bpf_xdp_ct_lookup(ctx, &tuple, sizeof(tuple.ipv4),
                                         &ct_opts, sizeof(ct_opts));
  if (ct_opts.error != 0) {
    if (ct) {
      bpf_ct_release(ct);
    }
    if (ct_opts.error == -ENOENT)
      goto notfound;

    bpf_printk("error in conntrack lookup for %pI4:%d->%pI4:%d : %d", &saddr,
               bpf_ntohs(sport), &daddr, bpf_ntohs(dport), ct_opts.error);
    return XDP_ABORTED;
  }

  if (ct) {
    bpf_ct_release(ct);
    // Connection exists, allow the packet
#ifdef DEBUG
    bpf_printk("found kernel conntrack entry for %pI4:%d->%pI4:%d", &saddr,
               bpf_ntohs(sport), &daddr, bpf_ntohs(dport));
#endif
    return XDP_PASS;
  } else {
  notfound:
#ifdef DEBUG
    bpf_printk("kernel conntrack entry for %pI4:%d->%pI4:%d not found", &saddr,
               bpf_ntohs(sport), &daddr, bpf_ntohs(dport));
#endif
    return XDP_ABORTED;
  }
}
