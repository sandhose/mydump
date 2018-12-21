#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#define qr     flags >> 15 & 0x0001
#define opcode flags >> 11 & 0x000F
#define aa     flags >> 10 & 0x0001
#define tc     flags >> 9  & 0x0001
#define rd     flags >> 8  & 0x0001
#define ra     flags >> 7  & 0x0001
#define z      flags >> 4  & 0x0007
#define rcode  flags & 0x000F

struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

#endif
