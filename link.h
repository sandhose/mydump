#ifndef __LINK_H
#define __LINK_H

#include <stdint.h>

typedef void(*link_handler)(const uint32_t, const uint8_t*);
link_handler resolve_link_handler(const uint16_t);

#endif
