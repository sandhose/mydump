#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <stdint.h>

typedef void(*protocol_handler)(uint32_t, const uint8_t*);
protocol_handler resolve_protocol_handler(const uint16_t protocol);
void handle_protocol_payload(const uint16_t protocol, const uint32_t, const uint8_t *packet);

#endif
