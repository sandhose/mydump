#ifndef __ETHER_H
#define __ETHER_H

#include <stdint.h>

typedef void(*network_handler)(uint32_t, const uint8_t*);
network_handler resolve_network_handler(const uint16_t ether_type);
void handle_ether_payload(const uint16_t ether_type, const uint32_t, const uint8_t *packet);

#endif
