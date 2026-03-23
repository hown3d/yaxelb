#include "consts.h"
#include "csum.h"
#include "helpers/parsing.h"
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
  __array(values, struct backend_map);
} listener_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct five_tuple_t);
  __type(value, struct conntrack_entry);
  __uint(max_entries, 512);
} conntrack SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct listener_entry);
  __type(value, __u16);
  __uint(max_entries, 128);
} num_backends SEC(".maps");

static __always_inline struct backend *
select_backend(__be32 lb_ip, __u16 lb_port, __u8 lb_proto) {
  struct backend *back;

  struct listener_entry key = {
      .ip = lb_ip, .port = lb_port, .protocol = lb_proto};
  void *backend_map = bpf_map_lookup_elem(&listener_map, &key);
  if (backend_map == NULL) {
#ifdef DEBUG
    bpf_printk("listener { .ip = %pI4, .port = %d, .protocol = %d} (%x%x%x) "
               "not found in listener_map",
               &key.ip, bpf_ntohs(key.port), key.protocol, key.ip.s_addr,
               key.port, key.protocol);
#endif
    return back;
  }

  __u16 *num_back = bpf_map_lookup_elem(&num_backends, &key);
  if (!num_back) {
    return back;
  }

  __u32 index = bpf_get_prandom_u32() % *num_back;

  return bpf_map_lookup_elem(backend_map, &index);
}

// count_packets atomically increases a
// packet counter on every invocation.
SEC("xdp")
int load_balance(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  int eth_type, ip_type;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct tcphdr *tcph;

  /* Default action XDP_PASS, imply everything we couldn't parse, or that
   * we don't want to deal with, we just pass up the stack and let the
   * kernel deal with it.
   */
  __u32 action = XDP_PASS; /* Default action */

  /* These keep track of the next header type and iterator pointer */
  struct hdr_cursor nh;
  nh.pos = data;

  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type < 0) {
#ifdef DEBUG
    bpf_printk("error parsing ethhdr");
#endif
    goto out;
  }
  if (eth_type != bpf_htons(ETH_P_IP)) {
#ifdef DEBUG
    bpf_printk("eth proto is not ip, got 0x%x", bpf_ntohs(eth_type));
#endif
    goto out;
  }

  ip_type = parse_iphdr(&nh, data_end, &iph);
  if (ip_type < 0) {
#ifdef DEBUG
    bpf_printk("error parsing iphdr");
#endif
    goto out;
  }

  if (ip_type != IPPROTO_TCP) {
#ifdef DEBUG
    bpf_printk("ip proto is not tcp, got %d", ip_type);
#endif
    goto out;
  }

  if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
#ifdef DEBUG
    bpf_printk("bad tcp header");
#endif
    action = XDP_ABORTED;
    goto out;
  }

  bpf_printk("got tcp packet: src %pI4:%d dst %pI4:%d", &iph->saddr,
             bpf_ntohs(tcph->source), &iph->daddr, bpf_ntohs(tcph->dest));

  struct five_tuple_t in = {
      .src_ip = iph->saddr,
      .dst_ip = iph->daddr,
      .dst_port = tcph->dest,
      .src_port = tcph->source,
      .protocol = ip_type,
  };

  struct conntrack_entry *conn = bpf_map_lookup_elem(&conntrack, &in);
  if (conn) {
#ifdef DEBUG
    bpf_printk("conntrack entry for entry found: %pI4:%d -> %pI4:%d",
               &conn->src_ip, bpf_ntohs(conn->src_port), &conn->dst_ip,
               bpf_ntohs(conn->dst_port));
#endif

    struct tcphdr tcph_old = *tcph;
    tcph->source =
        conn->dst_port; // original dst port (load balancer listener port)
    tcph->dest = conn->src_port; // original src port (client src port)
    int tcpcsum = tcp_csum(tcph_old.check, &tcph_old, tcph);
    if (tcpcsum < 0) {
#ifdef DEBUG
      bpf_printk("failed to update tcp checksum");
#endif
      action = XDP_ABORTED;
      goto out;
    }
    tcph->check = tcpcsum;

    iph->saddr = conn->dst_ip.s_addr; // original dst ip (load balancer)
    iph->daddr = conn->src_ip.s_addr; // original source ip (client)
    // recalc checksum
    iph->check = iph_csum(iph);
  } else {
#ifdef DEBUG
    bpf_printk("conntrack entry for entry not found, creating new one");
#endif
    struct backend *backend = select_backend(iph->daddr, tcph->dest, ip_type);
    if (!backend) {
#ifdef DEBUG
      bpf_printk("no backends not found");
#endif
      action = XDP_ABORTED;
      goto out;
    }

#ifdef DEBUG
    bpf_printk("new backend: %pI4:%d", &backend->ip, bpf_ntohs(backend->port));
#endif

    // when the backend responds:
    // - source ip + src port is backend IP and backend port
    // - destination is loadbalancer ip + original source port
    struct five_tuple_t in_loadbalancer = {
        .src_ip = backend->ip, // Backend IP
        .dst_ip = iph->daddr,  //  LB IP
        .dst_port = tcph->source,
        .src_port = backend->port,
        .protocol = ip_type,
    };

    struct conntrack_entry new_conn = {
        .src_ip.s_addr = iph->saddr,
        .dst_ip.s_addr = iph->daddr,
        .src_port = tcph->source,
        .dst_port = tcph->dest,
    };

    if (bpf_map_update_elem(&conntrack, &in_loadbalancer, &new_conn, BPF_ANY) <
        0) {
      bpf_printk("failed to update conntrack entry");
      action = XDP_ABORTED;
      goto out;
    }

    struct tcphdr tcph_old = *tcph;
    tcph->dest = backend->port;
    int tcpcsum = tcp_csum(tcph_old.check, &tcph_old, tcph);
    if (tcpcsum < 0) {
#ifdef DEBUG
      bpf_printk("failed to update tcp checksum");
#endif
      action = XDP_ABORTED;
      goto out;
    }
    tcph->check = tcpcsum;

    iph->saddr = iph->daddr;
    iph->daddr = backend->ip.s_addr;
    // recalc checksum
    iph->check = iph_csum(iph);
  }

out:
  return action;
}

char __license[] SEC("license") = "Dual MIT/GPL";
