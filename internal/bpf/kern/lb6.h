#pragma once

#include "conntrack.h"
#include "consts.h"
#include "csum.h"
#include "fib_lookup.h"
#include "helpers/ip6.h"
#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct v6_five_tuple_t {
  union v6addr src_ip;
  union v6addr dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 protocol;
  __u8 _pad[3];
};

struct v6_listener_entry {
  union v6addr ip;
  __be16 port;
  __u8 protocol;
  __u8 _pad[1];
};

struct v6_conntrack_entry {
  union v6addr src_ip;
  union v6addr dst_ip;
  __be16 src_port;
  __be16 dst_port;
};

struct v6_backend {
  union v6addr ip;
  __be16 port;
  __u8 _pad[2];
};

struct v6_backend_map {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct v6_backend);
  __uint(max_entries, 256);
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __type(key, struct v6_listener_entry);
  __uint(max_entries, 16);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct v6_backend_map);
} v6_listener_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct v6_five_tuple_t);
  __type(value, struct v6_conntrack_entry);
  __uint(max_entries, 512);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} v6_conntrack SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct v6_listener_entry);
  __type(value, __u16);
  __uint(max_entries, 128);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} v6_num_backends SEC(".maps");

static __always_inline __u32 random_backend_index_v6(__u16 num_back) {
  return bpf_get_prandom_u32() % num_back;
}

static __always_inline __u32
hash_backend_index_v6(struct v6_five_tuple_t *five_tuple, __u16 num_back) {
  // This is a veeeery simple hash
  __u32 hash =
      five_tuple->src_ip.p1 | five_tuple->src_ip.p2 | five_tuple->src_ip.p3 |
      five_tuple->src_ip.p4 | five_tuple->dst_ip.p1 | five_tuple->dst_ip.p2 |
      five_tuple->dst_ip.p3 | five_tuple->dst_ip.p4 | five_tuple->src_port |
      five_tuple->dst_port | five_tuple->protocol;
  return hash % num_back;
}

static __always_inline enum backend_selection_error
select_backend_v6(struct v6_five_tuple_t *five_tuple,
                  struct v6_backend **backend) {

  struct v6_listener_entry key = {.ip = five_tuple->dst_ip,
                                  .port = five_tuple->dst_port,
                                  .protocol = five_tuple->protocol};
  void *backend_map = bpf_map_lookup_elem(&v6_listener_map, &key);
  if (backend_map == NULL) {
    return -ERR_LISTENER_NOT_FOUND;
  }

  __u16 *num_back = bpf_map_lookup_elem(&v6_num_backends, &key);
  if (num_back == NULL) {
    return -ERR_NO_BACKENDS;
  }

  __u32 index;
  switch (lb_algo) {
  case RANDOM:
    index = random_backend_index_v6(*num_back);
    break;
  case HASH:
    index = hash_backend_index_v6(five_tuple, *num_back);
    break;
  default:
    return -ERR_UNKNOWN_ALGORITHM;
  }
#if DEBUG >= DEBUG_MEDIUM
  bpf_printk("backend idx: %x", index);
#endif
  *backend = bpf_map_lookup_elem(backend_map, &index);
  return 0;
}

static __always_inline int lb6(struct xdp_md *ctx, struct ethhdr *eth,
                               struct ipv6hdr *ip6h, __be16 *src_port,
                               __be16 *dst_port, int ip_type,
                               __sum16 *l4_check) {
  struct v6_backend *backend;
  __u32 action = XDP_PASS;

#if DEBUG >= DEBUG_HIGH
  bpf_printk("got l4 packet: src %pI6:%d dst %pI6:%d", &ip6h->saddr,
             bpf_ntohs(*src_port), &ip6h->daddr, bpf_ntohs(*dst_port));
#endif

  if (bpf_ntohs(ip6h->daddr.in6_u.u6_addr16[0]) == 0xff02 ||
      bpf_ntohs(ip6h->saddr.in6_u.u6_addr16[0]) == 0xfe80) {
    bpf_printk("link local, skipping load balancing");
    return XDP_PASS;
  }

  struct v6_five_tuple_t in = {
      .dst_port = *dst_port,
      .src_port = *src_port,
      .protocol = ip_type,
  };
  ipv6_addr_copy(&in.src_ip, (union v6addr *)&ip6h->saddr);
  ipv6_addr_copy(&in.dst_ip, (union v6addr *)&ip6h->daddr);

  bpf_printk("checking conntrack for key: in={ .src_ip: %pI6, .dst_ip = "
             "%pI6, .src_port: %d, .dst_port: %d, .protocol: %d }",
             &in.src_ip, &in.dst_ip, bpf_ntohs(in.src_port),
             bpf_ntohs(in.dst_port), in.protocol);

  struct v6_conntrack_entry *conn = bpf_map_lookup_elem(&v6_conntrack, &in);
  union v6addr old_saddr;
  union v6addr old_daddr;
  ipv6_addr_copy(&old_saddr, (union v6addr *)&ip6h->saddr);
  ipv6_addr_copy(&old_daddr, (union v6addr *)&ip6h->daddr);
  __be32 old_sport = *src_port;
  __be32 old_dport = *dst_port;

  if (conn) {
#if DEBUG >= DEBUG_LOW
    bpf_printk("conntrack entry for entry found: %pI6:%d -> %pI6:%d",
               &conn->src_ip, bpf_ntohs(conn->src_port), &conn->dst_ip,
               bpf_ntohs(conn->dst_port));
#endif

    ipv6_addr_copy((union v6addr *)&ip6h->saddr,
                   &conn->dst_ip); // original dst ip (load balancer)

    ipv6_addr_copy((union v6addr *)&ip6h->daddr,
                   &conn->src_ip); // original source ip (client)

    *src_port =
        conn->dst_port; // original dst port (load balancer listener port)
    *dst_port = conn->src_port; // original src port (client src port)
  } else {
    int ret = select_backend_v6(&in, &backend);
    if (ret < 0) {
      if (ret == -ERR_LISTENER_NOT_FOUND) {
        // To ensure we don't drop returning packets from connections the LB
        // created, we will just let the kernel handle such packets.
        int conntrack_ret = lookup_kernel_conntrack_v6(
            ctx, (union v6addr *)&ip6h->saddr, *src_port,
            (union v6addr *)&ip6h->daddr, *dst_port, ip_type);
        if (conntrack_ret < 0) {
          if (conntrack_ret == -CONNTRACK_NOT_FOUND) {
#if DEBUG >= DEBUG_MEDIUM
            bpf_printk("listener { .ip = %pI6, .port = %d, .protocol = %d} "
                       "not found in listener_map",
                       &in.dst_ip, bpf_ntohs(in.dst_port), in.protocol);
#endif
            // TODO: for some reason there are no conntrack entries in IPV6 when
            // performing health checks. Must investigate. In order to not drop
            // returning packets from healthchecks, just pass to kernel stack
            return XDP_PASS;
          }
          return XDP_DROP;
        }
      }
      bpf_printk("error selecting backend: %d", ret);
      return XDP_ABORTED;
    }
    if (backend == NULL) {
      bpf_printk("no backend found");
      return XDP_ABORTED;
    }

#if DEBUG >= DEBUG_LOW
    bpf_printk("new backend: %pI6:%d", &backend->ip, bpf_ntohs(backend->port));
#endif

    // when the backend responds:
    // - source ip + src port is backend IP and backend port
    // - destination is loadbalancer ip + original source port
    struct v6_five_tuple_t in_loadbalancer = {
        .src_port = backend->port,
        .dst_port = *src_port,
        .protocol = ip_type,
    };

    ipv6_addr_copy(&in_loadbalancer.src_ip, &backend->ip); // Backend IP
    ipv6_addr_copy(&in_loadbalancer.dst_ip,
                   (union v6addr *)&ip6h->daddr); //  LB IP

    struct v6_conntrack_entry new_conn = {
        .src_port = *src_port,
        .dst_port = *dst_port,
    };
    ipv6_addr_copy(&new_conn.src_ip, (union v6addr *)&ip6h->saddr);
    ipv6_addr_copy(&new_conn.dst_ip, (union v6addr *)&ip6h->daddr);

#if DEBUG >= DEBUG_HIGH
    bpf_printk(
        "storing conntrack key: in_loadbalancer={ .src_ip: %pI6, .dst_ip = "
        "%pI6, .src_port: %d, .dst_port: %d, .protocol: %d }",
        &in_loadbalancer.src_ip, &in_loadbalancer.dst_ip,
        bpf_ntohs(in_loadbalancer.src_port),
        bpf_ntohs(in_loadbalancer.dst_port), in_loadbalancer.protocol);

    bpf_printk("storing conntrack value: new_conn={ .src_ip: %pI6, .dst_ip = "
               "%pI6, .src_port: %d, .dst_port: %d }",
               &new_conn.src_ip, &new_conn.dst_ip, bpf_ntohs(new_conn.src_port),
               bpf_ntohs(new_conn.dst_port));
#endif

    if (bpf_map_update_elem(&v6_conntrack, &in_loadbalancer, &new_conn,
                            BPF_ANY) < 0) {
      bpf_printk("failed to update conntrack entry");
      return XDP_ABORTED;
    }

    ipv6_addr_copy((union v6addr *)&ip6h->saddr, (union v6addr *)&ip6h->daddr);
    ipv6_addr_copy((union v6addr *)&ip6h->daddr, &backend->ip);
    *dst_port = backend->port;
  }
  // calculate tcp checksum
  *l4_check = l4_csum_v6(*l4_check, ip6h, &old_saddr, &old_daddr, old_sport,
                         old_dport, *src_port, *dst_port);

  bpf_printk("new l4 csum: 0x%04X", bpf_ntohs(*l4_check));

#if DEBUG >= DEBUG_MEDIUM
  bpf_printk("fib lookup");
#endif
  return fib_lookup_v6(ctx, eth, ip6h);
}
