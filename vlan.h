#ifndef __VLAN_H
#define __VLAN_H

#include <stdint.h>

// TODO: decode PRI, CFI
#define VLAN_VID_MASK 0x0FFF
struct vlan_hdr {
  u_int16_t vlan_vid;
  u_int16_t ether_type;
};

#endif
