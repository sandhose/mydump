#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "protocol.h"
#include "udp.h"
#include "util.h"

static void handle_icmp(uint32_t length, const uint8_t* packet) {
  struct icmp* icmp = (struct icmp*)packet;
  APPLY_OVERHEAD(struct icmp, length, packet);
  DEBUGF("ICMP type: 0x%02x", icmp->icmp_type);
}

static void handle_icmpv6(uint32_t length, const uint8_t* packet) {
  struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)packet;
  APPLY_OVERHEAD(struct icmp6_hdr, length, packet);
  DEBUGF("ICMPv6 type: 0x%02x", icmp6->icmp6_type);
}

static void handle_udp(uint32_t length, const uint8_t* packet) {
  struct udphdr* udp = (struct udphdr *)packet;
  APPLY_OVERHEAD(struct udphdr, length, packet);
  DEBUGF("UDP sport: %d, dport: %d, length: %d, checksum: %04x",
         htons(udp->uh_sport),
         htons(udp->uh_dport),
         htons(udp->uh_ulen),
         htons(udp->uh_sum))

  handle_udp_payload(htons(udp->uh_sport), htons(udp->uh_dport), length, packet);
}

static void handle_tcp(uint32_t length, const uint8_t* packet) {
  struct tcphdr* tcp = (struct tcphdr *)packet;
  APPLY_OVERHEAD(struct tcphdr, length, packet);
  DEBUGF("TCP sport: %d, dport: %d, checksum: %04x",
         htons(tcp->th_sport),
         htons(tcp->th_dport),
         htons(tcp->th_sum))
  // TODO: reassemble packets and handle application layer
}

static protocol_handler handlers[] = {
  [IPPROTO_ICMP] = handle_icmp,
  [IPPROTO_ICMPV6] = handle_icmpv6,
  [IPPROTO_UDP] = handle_udp,
  [IPPROTO_TCP] = handle_tcp,
};

protocol_handler resolve_protocol_handler(const uint16_t protocol_type) {
  if (protocol_type >= (sizeof(handlers) / sizeof(protocol_handler)))
    return NULL;
  return handlers[protocol_type];
}

void handle_protocol_payload(const uint16_t protocol, const uint32_t length, const uint8_t *packet) {
  protocol_handler handler = resolve_protocol_handler(protocol);
  if (handler == NULL) {
    WARNF("Unknown protocol %#04x", protocol);
    return;
  }

  handler(length, packet);
}
