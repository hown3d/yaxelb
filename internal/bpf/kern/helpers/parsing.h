#include "../consts.h"
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

  if (iph->ihl != 5) {
    // if len of ipv4 hdr is not equal to 20bytes that means that header
    // contains ip options, and we dont support
    return -1;
  }

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

#define TCP_MAXLEN 60

enum hdr_parse_err {
  ERR_INVALID_LEN = 1,
  ERR_TOO_LONG = 2,
};

static __always_inline int parse_tcphdr(struct hdr_cursor *cursor,
                                        void *data_end,
                                        struct tcphdr **tcphdr) {
  __u16 len;
  struct tcphdr *tcph = cursor->pos;

  if (tcph + 1 > data_end)
    return -ERR_INVALID_LEN;

  len = tcph->doff * 4;
  /* Sanity check packet field is valid */
  if (len < sizeof(*tcph) || len > TCP_MAXLEN)
    return -ERR_INVALID_LEN;

  /* Variable-length TCP header, need to use byte-based arithmetic */
  if (cursor->pos + len > data_end)
    return -ERR_TOO_LONG;

  cursor->pos += len;
  *tcphdr = tcph;

  return len;
}

static __always_inline int parse_udphdr(struct hdr_cursor *cursor,
                                        void *data_end,
                                        struct udphdr **udphdr) {
  __u16 len;
  struct udphdr *udph = cursor->pos;

  if (udph + 1 > data_end)
    return -ERR_INVALID_LEN;

  len = bpf_ntohs(udph->len) - sizeof(struct udphdr);

  cursor->pos = udph + 1;
  *udphdr = udph;

  return len;
}
