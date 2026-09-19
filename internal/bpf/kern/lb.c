#include "consts.h"
#include "helpers/parsing.h"
#include "lb4.h"
#include "lb6.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// count_packets atomically increases a
// packet counter on every invocation.
SEC("xdp")
int load_balance(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  int eth_type, ip_type;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct ipv6hdr *ip6h;
  __be16 *src_port, *dst_port;
  __sum16 *check;

  /* Default action XDP_PASS, imply everything we couldn't parse, or that
   * we don't want to deal with, we just pass up the stack and let the
   * kernel deal with it.
   */
  __u32 action = XDP_PASS; /* Default action */

  /* These keep track of the next header type and iterator pointer */
  struct hdr_cursor cursor;
  cursor.pos = data;

  eth_type = parse_ethhdr(&cursor, data_end, &eth);
  if (eth_type < 0) {
#if DEBUG >= DEBUG_HIGH
    bpf_printk("error parsing ethhdr");
#endif
    goto out;
  }

  switch (eth_type) {
  case bpf_htons(ETH_P_IP): {
    ip_type = parse_iphdr(&cursor, data_end, &iph);
    break;
  }
  case bpf_htons(ETH_P_IP6): {
    ip_type = parse_ip6hdr(&cursor, data_end, &ip6h);
    break;
  }
  default:
#if DEBUG >= DEBUG_HIGH
    bpf_printk("ip proto unknown, got %d", bpf_ntohs(eth_type));
#endif
    goto out;
  }
  if (ip_type < 0) {
#if DEBUG >= DEBUG_HIGH
    bpf_printk("failed to parse network header");
#endif
    goto out;
  }

  switch (ip_type) {
  case IPPROTO_TCP: {
    struct tcphdr *tcph;
    int ret = parse_tcphdr(&cursor, data_end, &tcph);
    if (ret < 0) {
#if DEBUG >= DEBUG_HIGH
      bpf_printk("bad tcp header %d", ret);
#endif
      action = XDP_ABORTED;
      goto out;
    }
    check = &tcph->check;
    src_port = &tcph->source;
    dst_port = &tcph->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udph;
    int ret = parse_udphdr(&cursor, data_end, &udph);
    if (ret < 0) {
#if DEBUG >= DEBUG_HIGH
      bpf_printk("bad udp header %d", ret);
#endif
      action = XDP_ABORTED;
      goto out;
    }
    check = &udph->check;
    src_port = &udph->source;
    dst_port = &udph->dest;
    break;
  }
  default: {
#if DEBUG >= DEBUG_HIGH
    bpf_printk("ip proto is neither udp or tcp, got %d", ip_type);
#endif
    goto out;
  }
  }

  switch (eth_type) {
  case bpf_htons(ETH_P_IP):
    action = lb4(ctx, eth, iph, src_port, dst_port, ip_type, check);
    break;
  case bpf_htons(ETH_P_IP6):
    action = lb6(ctx, eth, ip6h, src_port, dst_port, ip_type, check);
    break;
  default:
    action = XDP_ABORTED;
    break;
  }

out:
#if DEBUG >= DEBUG_MEDIUM
  bpf_printk("action %d", action);
#endif
  return action;
}

char __license[] SEC("license") = "Dual MIT/GPL";
