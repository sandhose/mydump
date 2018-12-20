#ifndef __UDP_H
#define __UDP_H

#include <stdint.h>

typedef void(*udp_handler)(uint32_t, const uint8_t*);
udp_handler resolve_udp_handler(const uint16_t port);
void handle_udp_payload(const uint16_t sport, const uint16_t dport,
                        const uint32_t, const uint8_t *packet);

#endif
