#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "ether.h"
#include "vlan.h"
#include "protocol.h"
#include "util.h"

static void handle_unknown(uint32_t length, const uint8_t *packet) {
  (void)packet;
  DEBUGF("Unhandled network packet (length: %d)", length);
}

static void handle_ip(uint32_t length, const uint8_t *packet) {
  struct ip *ip = (struct ip *)packet;
  APPLY_OVERHEAD(struct ip, length, packet);
  DEBUGF("IPv4 packet src: %s, dst: %s, protocol: %#08x",
         inet_ntoa(ip->ip_src),
         inet_ntoa(ip->ip_dst),
         ip->ip_p);
  handle_protocol_payload(ip->ip_p, length, packet);
}

static void handle_ip6(uint32_t length, const uint8_t *packet) {
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  APPLY_OVERHEAD(struct ip6_hdr, length, packet);
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  DEBUGF("IPv6 packet src:[%s], dst:[%s], protocol: %#08x",
         inet_ntop(AF_INET6, &(ip6->ip6_src), src, INET6_ADDRSTRLEN),
         inet_ntop(AF_INET6, &(ip6->ip6_dst), dst, INET6_ADDRSTRLEN),
         ip6->ip6_nxt);
  handle_protocol_payload(ip6->ip6_nxt, length, packet);
}

static void handle_vlan(uint32_t length, const uint8_t *packet) {
  struct vlan_hdr *vlan = (struct vlan_hdr *)packet;
  APPLY_OVERHEAD(struct vlan_hdr, length, packet);
  DEBUGF("VLAN vid: %d, type: %04x",
         htons(vlan->vlan_vid) & VLAN_VID_MASK, htons(vlan->ether_type));
  handle_ether_payload(htons(vlan->ether_type), length, packet);
}

static void handle_arp(uint32_t length, const uint8_t *packet) {
  struct arphdr *arp = (struct arphdr *)packet;
  APPLY_OVERHEAD(struct arphdr, length, packet);
  uint16_t op = htons(arp->ar_op);

  if ((arp->ar_hln + arp->ar_pln) * 2 > length) {
    WARNF("ARP packet too small (op: %04x, hrd: %04x, pro: %04x, hln: %d, pln: %d)",
          op, htons(arp->ar_hrd), htons(arp->ar_pro), arp->ar_hln, arp->ar_pln);
    return;
  }

  // Let's assume it's IPv4 over ethernet for now.
  struct ether_addr *sha = (struct ether_addr *)packet;
  packet += arp->ar_hln;
  length -= arp->ar_hln;
  struct in_addr *spa = (struct in_addr *)packet;
  packet += arp->ar_pln;
  length -= arp->ar_pln;
  struct ether_addr *tha = (struct ether_addr *)packet;
  packet += arp->ar_hln;
  length -= arp->ar_hln;
  struct in_addr *tpa = (struct in_addr *)packet;
  packet += arp->ar_pln;
  length -= arp->ar_pln;

  switch (op) {
    case ARPOP_REQUEST:
      DEBUGF("ARP request, who has %s (%s)? Tell %s (%s)", inet_ntoa(*tpa), ether_ntoa(tha), inet_ntoa(*spa), ether_ntoa(sha));
      break;
    case ARPOP_REPLY:
      DEBUGF("ARP reply, %s is at %s", inet_ntoa(*spa), ether_ntoa(sha));
      break;
    default:
      DEBUGF("Unhandled ARP op: %04x, tpa: %s, tha: %s, spa: %s, sha: %s",
             op, inet_ntoa(*tpa), ether_ntoa(tha), inet_ntoa(*spa), ether_ntoa(sha));
      break;
  }

  if (length > 0) {
    WARN("Garbage after ARP packet");
    handle_raw(length, packet);
  }
}

static network_handler handlers[] = {
  [ETHERTYPE_IP] = handle_ip,
  [ETHERTYPE_IPV6] = handle_ip6,
  [ETHERTYPE_PUP] = handle_unknown,
  [ETHERTYPE_ARP] = handle_arp,
  [ETHERTYPE_REVARP] = handle_unknown,
  [ETHERTYPE_VLAN] = handle_vlan,
  [ETHERTYPE_PAE] = handle_unknown,
  [ETHERTYPE_RSN_PREAUTH] = handle_unknown,
  [ETHERTYPE_PTP] = handle_unknown,
  [ETHERTYPE_LOOPBACK] = handle_unknown,
};

network_handler resolve_network_handler(const uint16_t ether_type) {
  if (ether_type >= (sizeof(handlers) / sizeof(network_handler)))
    return NULL;
  return handlers[ether_type];
}

void handle_ether_payload(const uint16_t ether_type, const uint32_t length, const uint8_t *packet) {
  network_handler handler = resolve_network_handler(ether_type);
  if (handler == NULL) {
    WARNF("Unknown ethertype %#04x", ether_type);
    return;
  }

  handler(length, packet);
}
