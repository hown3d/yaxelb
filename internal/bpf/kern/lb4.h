#pragma once

#include "conntrack.h"
#include "consts.h"
#include "csum.h"
#include "fib_lookup.h"
#include "helpers/parsing.h"
#include "types.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct five_tuple_t {
  struct in_addr src_ip;
  struct in_addr dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 protocol;
  __u8 _pad[3];
};

struct listener_entry {
  struct in_addr ip;
  __be16 port;
  __u8 protocol;
  __u8 _pad[1];
};

struct conntrack_entry {
  struct in_addr src_ip;
  struct in_addr dst_ip;
  __be16 src_port;
  __be16 dst_port;
};

struct backend {
  struct in_addr ip;
  __be16 port;
  __u8 _pad[2];
};

struct backend_map {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct backend);
  __uint(max_entries, 256);
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __type(key, struct listener_entry);
  __uint(max_entries, 16);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct backend_map);
} listener_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct five_tuple_t);
  __type(value, struct conntrack_entry);
  __uint(max_entries, 512);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct listener_entry);
  __type(value, __u16);
  __uint(max_entries, 128);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} num_backends SEC(".maps");

static __always_inline __u32 random_backend_index(__u16 num_back) {
  return bpf_get_prandom_u32() % num_back;
}

static __always_inline __u32 hash_backend_index(struct five_tuple_t *five_tuple,
                                                __u16 num_back) {
  // This is a veeeery simple hash
  __u32 hash = five_tuple->src_ip.s_addr | five_tuple->dst_ip.s_addr |
               five_tuple->src_port | five_tuple->dst_port |
               five_tuple->protocol;
  return hash % num_back;
}

static __always_inline enum backend_selection_error
select_backend(struct five_tuple_t *five_tuple, struct backend **backend) {

  struct listener_entry key = {.ip = five_tuple->dst_ip,
                               .port = five_tuple->dst_port,
                               .protocol = five_tuple->protocol};
  void *backend_map = bpf_map_lookup_elem(&listener_map, &key);
  if (backend_map == NULL) {
    return -ERR_LISTENER_NOT_FOUND;
  }

  __u16 *num_back = bpf_map_lookup_elem(&num_backends, &key);
  if (num_back == NULL) {
    return -ERR_NO_BACKENDS;
  }

  __u32 index;
  switch (lb_algo) {
  case RANDOM:
    index = random_backend_index(*num_back);
    break;
  case HASH:
    index = hash_backend_index(five_tuple, *num_back);
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

static __always_inline int lb4(struct xdp_md *ctx, struct ethhdr *eth,
                               struct iphdr *iph, __be16 *src_port,
                               __be16 *dst_port, int ip_type,
                               __sum16 *l4_check) {
  struct backend *backend;
  __u32 action = XDP_PASS;

#if DEBUG >= DEBUG_HIGH
  bpf_printk("got l4 packet: src %pI4:%d dst %pI4:%d", &iph->saddr,
             bpf_ntohs(*src_port), &iph->daddr, bpf_ntohs(*dst_port));
#endif

  struct five_tuple_t in = {
      .src_ip = iph->saddr,
      .dst_ip = iph->daddr,
      .dst_port = *dst_port,
      .src_port = *src_port,
      .protocol = ip_type,
  };
  bpf_printk("checking conntrack for key: in={ .src_ip: %pI4, .dst_ip = "
             "%pI4, .src_port: %d, .dst_port: %d, .protocol: %d }",
             &in.src_ip, &in.dst_ip, bpf_ntohs(in.src_port),
             bpf_ntohs(in.dst_port), in.protocol);

  struct conntrack_entry *conn = bpf_map_lookup_elem(&conntrack, &in);
  __be32 old_saddr = iph->saddr;
  __be32 old_daddr = iph->daddr;
  __be32 old_sport = *src_port;
  __be32 old_dport = *dst_port;

  if (conn) {
#if DEBUG >= DEBUG_LOW
    bpf_printk("conntrack entry for entry found: %pI4:%d -> %pI4:%d",
               &conn->src_ip, bpf_ntohs(conn->src_port), &conn->dst_ip,
               bpf_ntohs(conn->dst_port));
#endif

    iph->saddr = conn->dst_ip.s_addr; // original dst ip (load balancer)
    iph->daddr = conn->src_ip.s_addr; // original source ip (client)

    *src_port =
        conn->dst_port; // original dst port (load balancer listener port)
    *dst_port = conn->src_port; // original src port (client src port)
  } else {
    int ret = select_backend(&in, &backend);
    if (ret < 0) {
      if (ret == -ERR_LISTENER_NOT_FOUND) {
        // To ensure we don't drop returning packets from connections the LB
        // created, we will just let the kernel handle such packets.
        int conntrack_ret = lookup_kernel_conntrack_v4(
            ctx, iph->saddr, *src_port, iph->daddr, *dst_port, ip_type);
        if (conntrack_ret < 0) {
          action = XDP_DROP;
          if (conntrack_ret == -CONNTRACK_NOT_FOUND) {
#if DEBUG >= DEBUG_MEDIUM
            bpf_printk("listener { .ip = %pI4, .port = %d, .protocol = %d} "
                       "not found in listener_map",
                       &in.dst_ip, bpf_ntohs(in.dst_port), in.protocol);
#endif
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
    bpf_printk("new backend: %pI4:%d", &backend->ip, bpf_ntohs(backend->port));
#endif

    // when the backend responds:
    // - source ip + src port is backend IP and backend port
    // - destination is loadbalancer ip + original source port
    struct five_tuple_t in_loadbalancer = {
        .src_ip = backend->ip, // Backend IP
        .dst_ip = iph->daddr,  //  LB IP
        .src_port = backend->port,
        .dst_port = *src_port,
        .protocol = ip_type,
    };
    struct conntrack_entry new_conn = {
        .src_ip.s_addr = iph->saddr,
        .dst_ip.s_addr = iph->daddr,
        .src_port = *src_port,
        .dst_port = *dst_port,
    };

#if DEBUG >= DEBUG_HIGH
    bpf_printk(
        "storing conntrack key: in_loadbalancer={ .src_ip: %pI4, .dst_ip = "
        "%pI4, .src_port: %d, .dst_port: %d, .protocol: %d }",
        &in_loadbalancer.src_ip, &in_loadbalancer.dst_ip,
        bpf_ntohs(in_loadbalancer.src_port),
        bpf_ntohs(in_loadbalancer.dst_port), in_loadbalancer.protocol);

    bpf_printk("storing conntrack value: new_conn={ .src_ip: %pI4, .dst_ip = "
               "%pI4, .src_port: %d, .dst_port: %d }",
               &new_conn.src_ip, &new_conn.dst_ip, bpf_ntohs(new_conn.src_port),
               bpf_ntohs(new_conn.dst_port));
#endif

    if (bpf_map_update_elem(&conntrack, &in_loadbalancer, &new_conn, BPF_ANY) <
        0) {
      bpf_printk("failed to update conntrack entry");
      return XDP_ABORTED;
    }

    iph->saddr = iph->daddr;
    iph->daddr = backend->ip.s_addr;
    *dst_port = backend->port;
  }
  // recalc checksum
  iph->check = iph_csum(iph);
  // calculate tcp checksum
  *l4_check = l4_csum_v4(*l4_check, iph, old_saddr, old_daddr, old_sport,
                         old_dport, *src_port, *dst_port);

  bpf_printk("new l4 csum: 0x%04X", bpf_ntohs(*l4_check));

#if DEBUG >= DEBUG_MEDIUM
  bpf_printk("fib lookup");
#endif
  return fib_lookup_v4(ctx, eth, iph);
}
