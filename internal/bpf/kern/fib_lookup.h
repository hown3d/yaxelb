#include "consts.h"
#include "helpers/ip.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

static int __always_inline fib_lookup_v4(struct xdp_md *ctx, struct ethhdr *eth,
                                         struct iphdr *ip4) {

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return -EINVAL;
  }

  struct bpf_fib_lookup fib_params = {};
  fib_params.ifindex = ctx->ingress_ifindex;
  fib_params.family = AF_INET;
  fib_params.tos = ip4->tos;
  fib_params.l4_protocol = ip4->protocol;
  fib_params.tot_len = bpf_ntohs(ip4->tot_len);
  fib_params.ipv4_src = ip4->saddr;
  fib_params.ipv4_dst = ip4->daddr;

  int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
  switch (ret) {
  case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
    __builtin_memcpy(eth->h_source, fib_params.smac, sizeof(fib_params.smac));
    __builtin_memcpy(eth->h_dest, fib_params.dmac, sizeof(fib_params.dmac));
#ifdef DEBUG
    bpf_printk("FIB lookup returned success");
    bpf_printk("FIB lookup: recieved smac: %02x:%02x:%02x:%02x:%02x:%02x",
               fib_params.smac[0], fib_params.smac[1], fib_params.smac[2],
               fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
    bpf_printk("FIB lookup: recieved dmac: %02x:%02x:%02x:%02x:%02x:%02x",
               fib_params.dmac[0], fib_params.dmac[1], fib_params.dmac[2],
               fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
    bpf_printk("FIB lookup: ifindex %d", fib_params.ifindex);
#endif

    return bpf_redirect(fib_params.ifindex, 0);
  case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
  case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
  case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
  case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
  case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    return XDP_DROP;
  case BPF_FIB_LKUP_RET_NO_NEIGH:    /* no neighbor entry for nh */
  case BPF_FIB_LKUP_RET_FRAG_NEEDED: /* fragmentation required to fwd */
    bpf_printk("fib lookup code: %d, passing", ret);
    return XDP_PASS;
  }
  bpf_printk("unknown fib lookup code: %d", ret);
  return XDP_ABORTED;
}
