#pragma once

#include "helpers/ip6.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static __always_inline int _lookup_socket(struct xdp_md *ctx,
                                          struct bpf_sock_tuple *tuple,
                                          size_t tuple_len, u8 proto) {
  struct bpf_sock *sk;

  if (proto == IPPROTO_TCP) {
    sk = bpf_sk_lookup_tcp(ctx, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
  } else if (proto == IPPROTO_UDP) {
    sk = bpf_sk_lookup_tcp(ctx, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
  }
  if (!sk)
    return -1;

  bpf_sk_release(sk);
  return 0;
}

static __always_inline int lookup_socket_v4(struct xdp_md *ctx, __be32 saddr,
                                            __be16 sport, __be32 daddr,
                                            __be16 dport, u8 proto) {
  struct bpf_sock_tuple tuple;
  size_t tuple_len;

  tuple.ipv4.saddr = saddr;
  tuple.ipv4.daddr = daddr;
  tuple.ipv4.sport = sport;
  tuple.ipv4.dport = dport;
  tuple_len = sizeof(tuple.ipv4);
  return _lookup_socket(ctx, &tuple, tuple_len, proto);
}

static __always_inline int lookup_socket_v6(struct xdp_md *ctx,
                                            union v6addr *saddr, __be16 sport,
                                            union v6addr *daddr, __be16 dport,
                                            u8 proto) {
  struct bpf_sock_tuple tuple;
  struct bpf_sock *sk;
  size_t tuple_len;

  ipv6_addr_copy((union v6addr *)&tuple.ipv6.saddr, saddr);
  ipv6_addr_copy((union v6addr *)&tuple.ipv6.daddr, daddr);
  tuple.ipv6.sport = sport;
  tuple.ipv6.dport = dport;
  tuple_len = sizeof(tuple.ipv6);

  return _lookup_socket(ctx, &tuple, tuple_len, proto);
}
