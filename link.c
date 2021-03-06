#ifndef __MACH__
#include <netinet/ether.h>
#endif

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap/dlt.h>
#include <ctype.h>

#include "aftypes.h"
#include "ether.h"
#include "link.h"
#include "util.h"

// Linux SLL devices, i.e. when capturing on the `any` interface
#ifdef DLT_LINUX_SLL
struct linux_sll_header {
  uint16_t sent_by;
  uint16_t address_type;
  uint16_t address_length;
  uint8_t source_address[8];
  uint16_t ether_type;
};

static void handle_linux_sll(uint32_t length, const uint8_t *packet) {
  // TODO: check the address type
  struct linux_sll_header *linux_sll = (struct linux_sll_header *)packet;
  APPLY_OVERHEAD(struct linux_sll_header, length, packet);
  DEBUGF("Linux SLL packet addr: %s, type: 0x%04x, length: %d",
         ether_ntoa((struct ether_addr *)linux_sll->source_address),
         htons(linux_sll->ether_type),
         length);
  PRINTF("Linux SLL %s, ",
         ether_ntoa((struct ether_addr *)linux_sll->source_address));
  handle_ether_payload(htons(linux_sll->ether_type), length, packet);
}
#endif

// Loopback devices
#ifdef DLT_NULL
uint16_t af_to_ethertype(u_int16_t af) {
  switch (af) {
    case BSD_AF_INET:
    //   LINUX_AF_INET:
    //   SOLARIS_AF_INET:
    //   WINSOCK_AF_INET:
      return ETHERTYPE_IP;

    case BSD_AF_INET6_BSD:
    case BSD_AF_INET6_FREEBSD:
    case BSD_AF_INET6_DARWIN:
    case SOLARIS_AF_INET6:
    case LINUX_AF_INET6:
    case WINSOCK_AF_INET6:
      return ETHERTYPE_IPV6;

    default:
      return 0;
  }
}

struct null_header {
  u_int32_t af_type;
};

static void handle_null(uint32_t length, const uint8_t *packet) {
  struct null_header* null = (struct null_header *)packet;
  APPLY_OVERHEAD(struct null_header, length, packet);

  DEBUGF("Null packet type: 0x%04x, length: %d", null->af_type, length);
  PRINTF("Loopback, ");
  handle_ether_payload(af_to_ethertype(null->af_type), length, packet);
}
#endif

// Ethernet devices
void handle_ethernet(uint32_t length, const uint8_t *packet) {
  struct ether_header *ethernet = (struct ether_header *)packet;
  APPLY_OVERHEAD(struct ether_header, length, packet);

  DEBUGF("Ethernet packet dst: %s, src: %s, type: 0x%04x, length: %d",
         ether_ntoa((struct ether_addr *)ethernet->ether_dhost),
         ether_ntoa((struct ether_addr *)ethernet->ether_shost),
         htons(ethernet->ether_type),
         length);
  PRINTF("Ethernet %s -> %s, ",
         ether_ntoa((struct ether_addr *)ethernet->ether_dhost),
         ether_ntoa((struct ether_addr *)ethernet->ether_shost));
  handle_ether_payload(htons(ethernet->ether_type), length, packet);
}

static link_handler handlers[] = {
#ifdef DLT_NULL
  [DLT_NULL] = handle_null,
#endif
#ifdef DLT_EN10MB
  [DLT_EN10MB] = handle_ethernet,
#endif
#ifdef DLT_RAW
  [DLT_RAW] = handle_raw,
#endif
#ifdef DLT_LINUX_SLL
  [DLT_LINUX_SLL] = handle_linux_sll,
#endif
};

link_handler resolve_link_handler(const uint16_t link_type) {
  if (link_type >= (sizeof(handlers) / sizeof(link_handler)))
    return NULL;
  return handlers[link_type];
}
