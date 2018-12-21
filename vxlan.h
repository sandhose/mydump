#ifndef __VXLAN_H
#define __VXLAN_H

#include <stdint.h>

#define vni vni_reserved >> 4
struct vxlan_hdr {
  u_int16_t flags;
  u_int16_t group_policy;
  u_int32_t vni_reserved;
};

#endif
