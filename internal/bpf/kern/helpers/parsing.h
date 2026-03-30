#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct hdr_cursor {
  void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *cursor,
                                        void *data_end,
                                        struct ethhdr **ethhdr) {
  struct ethhdr *eth = cursor->pos;
  int hdrsize = sizeof(*eth);

  /* Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
  if (cursor->pos + hdrsize > data_end)
    return -1;

  cursor->pos += hdrsize;
  *ethhdr = eth;

  return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *cursor,
                                       void *data_end, struct iphdr **iphdr) {

  struct iphdr *iph = cursor->pos;
  int hdrsize;

  if (iph + 1 > data_end)
    return -1;

  hdrsize = iph->ihl * 4;
  /* Sanity check packet field is valid */
  if (hdrsize < sizeof(*iph))
    return -1;

  /* Variable-length IPv4 header, need to use byte-based arithmetic */
  if (cursor->pos + hdrsize > data_end)
    return -1;

  cursor->pos += hdrsize;
  *iphdr = iph;
  return iph->protocol;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *cursor,
                                        void *data_end,
                                        struct tcphdr **tcphdr) {
  int len;
  struct tcphdr *h = cursor->pos;

  if (h + 1 > data_end)
    return -1;

  len = h->doff * 4;
  /* Sanity check packet field is valid */
  if (len < sizeof(*h))
    return -1;

  /* Variable-length TCP header, need to use byte-based arithmetic */
  if (cursor->pos + len > data_end)
    return -1;

  cursor->pos += len;
  *tcphdr = h;

  return len;
}
