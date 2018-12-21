#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/bootp.h>

#include "dns.h"
#include "udp.h"
#include "util.h"
#include "link.h"
#include "vxlan.h"

#define DHCP_MAGIC 0x63538263

static char* dhcp_msgtype[] = {
  [1] = "DHCPDISCOVER",
  [2] = "DHCPOFFER",
  [3] = "DHCPREQUEST",
  [4] = "DHCPDECLINE",
  [5] = "DHCPACK",
  [6] = "DHCPNAK",
  [7] = "DHCPRELEASE",
  [8] = "DHCPINFORM",
  [9] = "DHCPFORCERENEW",
  [10] = "DHCPLEASEQUERY",
  [11] = "DHCPLEASEUNASSIGNED",
  [12] = "DHCPLEASEUNKNOWN",
  [13] = "DHCPLEASEACTIVE",
  [14] = "DHCPBULKLEASEQUERY",
  [15] = "DHCPLEASEQUERYDONE",
  [16] = "DHCPACTIVELEASEQUERY",
  [17] = "DHCPLEASEQUERYSTATUS",
  [18] = "DHCPTLS"
};

static char* format_addresses(uint32_t count, const struct in_addr *ips) {
  static char buf[256];
  size_t off = 0;
  for (uint8_t i = 0; i < count; i++)
    off += sprintf(buf + off, "%s, ", inet_ntoa(ips[i]));
  buf[off - 2] = '\0';
  return buf;
}

static char* truncate(uint8_t length, const uint8_t* payload) {
  static char buf[256];
  memcpy(buf, payload, length);
  buf[length] = '\0';
  return buf;
}

static void handle_bootp(uint32_t length, const uint8_t* packet) {
  struct bootp *bootp = (struct bootp *)packet;
  APPLY_OVERHEAD_S(sizeof(struct bootp) - 64, length, packet);

  DEBUGF("BOOTP op:%x htype:%x len:%d hops:%d xid:%x", bootp->bp_op, bootp->bp_htype, bootp->bp_hlen, bootp->bp_hops, bootp->bp_xid);

  int *magic = (int *)packet;
  APPLY_OVERHEAD(int, length, packet);
  if (*magic == DHCP_MAGIC) {
    u_char opt;
    while(length > 0 && (opt = *packet) != 0xFF) {
      APPLY_OVERHEAD(char, length, packet);
      u_char *optlen = (u_char *)packet;
      APPLY_OVERHEAD(char, length, packet);
      u_char *optpayload = (u_char *)packet;
      APPLY_OVERHEAD_S(*optlen, length, packet);

      indent_log();
      switch (opt) {
        case 0: // Pad
          break;

        case 1: // Network mask
          DEBUGF("Network mask %s", inet_ntoa(*(struct in_addr *)optpayload));
          break;

        case 3: // Router
          DEBUGF("Router %s", format_addresses(*optlen / 4, (struct in_addr *)optpayload));
          break;

        case 6: // Domain Name Server
          DEBUGF("Domain Name Server %s", format_addresses(*optlen / 4, (struct in_addr *)optpayload));
          break;

        case 12: // Hostname
          DEBUGF("Hostname %s", truncate(*optlen, optpayload));
          break;

        case 15: // Domain Name
          DEBUGF("Domain Name %s", truncate(*optlen, optpayload));
          break;

        case 50: // Requested IP Address
          DEBUGF("Requested IP Address %s", inet_ntoa(*(struct in_addr *)optpayload));
          break;

        case 51: // Lease time
          DEBUGF("Lease time %d", htonl(*(uint32_t *)optpayload));
          break;

        case 53: // DHCP msg type
          if (*optpayload < sizeof(dhcp_msgtype) && dhcp_msgtype[*optpayload]) {
            DEBUGF("DHCP message type %s", dhcp_msgtype[*optpayload]);
          } else {
            WARNF("Unknown DHCP message type %d", *optpayload);
          }
          break;

        case 54: // Server Identifier
          DEBUGF("Server Identifier %s", inet_ntoa(*(struct in_addr *)optpayload));
          break;

        case 55: // Parameter Request List
        {
          char buf[1024];
          size_t off = 0;
          for (uint8_t i = 0; i < *optlen; i++)
            off += sprintf(buf + off, "%d, ", optpayload[i]);
          buf[off - 2] = '\0';

          DEBUGF("Parameter Request List %s", buf);
          break;
        }

        case 57: // Maximum DHCP Message Size
          DEBUGF("Maximum DHCP Message Size %d", htons(*(uint16_t *)optpayload));
          break;

        case 252: // WPAD
          DEBUGF("WPAD %s", truncate(*optlen, optpayload));
          break;

        default:
        {
          char buf[1024];
          size_t off = 0;
          for (uint8_t i = 0; i < *optlen; i++)
            off += sprintf(buf + off, "%02x ", optpayload[i]);
          buf[off - 1] = '\0';

          DEBUGF("DHCP option %3d (len: %2d): %s", opt, *optlen, buf);
          break;
        }
      }
      dedent_log();
    }
  }
}

static void handle_vxlan(uint32_t length, const uint8_t* packet) {
  struct vxlan_hdr *vxlan = (struct vxlan_hdr *)packet;
  APPLY_OVERHEAD(struct vxlan_hdr, length, packet);
  DEBUGF("VXLAN vni: 0x%06x", vxlan->vni);
  indent_log();
  handle_ethernet(length, packet);
  dedent_log();
}

static void handle_dns(uint32_t length, const uint8_t* packet) {
  struct dns_hdr *dns = (struct dns_hdr *)packet;
  APPLY_OVERHEAD(struct dns_hdr, length, packet);
  uint16_t qdcount = htons(dns->qdcount);
  uint16_t ancount = htons(dns->ancount);
  uint16_t nscount = htons(dns->nscount);
  uint16_t arcount = htons(dns->arcount);

  DEBUGF("DNS id:0x%04x qr:%d opcode:0x%02x aa:%d tc:%d rd:%d ra:%d z:%d rcode:%d qdcount:%d ancount:%d nscount:%d arcount:%d",
         htons(dns->id), dns->qr, dns->opcode, dns->aa, dns->tc, dns->rd, dns->ra, dns->z, dns->rcode,
         qdcount, ancount, nscount, arcount);
  // TODO: decode queries and answers
}

static udp_handler handlers[] = {
  [53] = handle_dns,
  [67] = handle_bootp,
  [68] = handle_bootp,
  [4789] = handle_vxlan,
};

udp_handler resolve_udp_handler(const uint16_t port) {
  if (port >= (sizeof(handlers) / sizeof(udp_handler)))
    return NULL;
  return handlers[port];
}

void handle_udp_payload(const uint16_t sport, const uint16_t dport, const uint32_t length, const uint8_t *packet) {
  udp_handler handler = resolve_udp_handler(dport);
  if (handler == NULL)
    handler = resolve_udp_handler(sport);

  indent_log();
  if (handler != NULL)
    handler(length, packet);
  else
    DEBUG("No UDP handler.");
  dedent_log();
}
