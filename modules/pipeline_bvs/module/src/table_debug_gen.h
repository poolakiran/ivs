/****************************************************************
 *
 *        Copyright 2016, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#ifndef TABLE_DEBUG_GEN_H
#define TABLE_DEBUG_GEN_H

/* reserved valid bit flags */
#define DEBUG_GEN_PRIORITY 0x1
#define DEBUG_GEN_IN_PORT  0x2

#define DEBUG_GEN_ATTRS                                                 \
    DEBUG_GEN_ATTR(eth_src, 0x4, ETH_SRC,                               \
                   of_mac_addr_t, of_mac_addr_all_ones)                 \
    DEBUG_GEN_ATTR(eth_dst, 0x8, ETH_DST,                               \
                   of_mac_addr_t, of_mac_addr_all_ones)                 \
    DEBUG_GEN_ATTR(eth_type, 0x10, ETH_TYPE, uint16_t, 0xffff)          \
    DEBUG_GEN_ATTR(vlan_vid, 0x20, VLAN_VID, uint16_t, 0xfff)           \
    DEBUG_GEN_ATTR(vrf, 0x40, VRF, uint32_t, 0xffffffff)                \
    DEBUG_GEN_ATTR(l3_src_class_id, 0x80, L3_SRC_CLASS_ID,              \
                   uint32_t, 0xffffffff)                                \
    DEBUG_GEN_ATTR(ipv4_src, 0x100, IPV4_SRC, of_ipv4_t, 0xffffffff)    \
    DEBUG_GEN_ATTR(ipv4_dst, 0x200, IPV4_DST, of_ipv4_t, 0xffffffff)    \
    DEBUG_GEN_ATTR(ipv6_src, 0x400, IPV6_SRC,                           \
                   of_ipv6_t, of_ipv6_all_ones)                         \
    DEBUG_GEN_ATTR(ipv6_dst, 0x800, IPV6_DST,                           \
                   of_ipv6_t, of_ipv6_all_ones)                         \
    DEBUG_GEN_ATTR(ip_proto, 0x1000, IP_PROTO, uint8_t, 0xff)           \
    DEBUG_GEN_ATTR(ecn, 0x4000, ECN, uint8_t, 0x3)                      \
    DEBUG_GEN_ATTR(dscp, 0x2000, DSCP, uint16_t, 0x3f)                  \
    DEBUG_GEN_ATTR(tcp_src, 0x8000, TCP_SRC, uint16_t, 0xffff)          \
    DEBUG_GEN_ATTR(tcp_dst, 0x10000, TCP_DST, uint16_t, 0xffff)         \
    DEBUG_GEN_ATTR(udp_src, 0x20000, UDP_SRC, uint16_t, 0xffff)         \
    DEBUG_GEN_ATTR(udp_dst, 0x40000, UDP_DST, uint16_t, 0xffff)         \
    DEBUG_GEN_ATTR(ingress_port_group_id, 0x80000,                      \
                   INGRESS_PORT_GROUP_ID, uint32_t, 0xffffff)           \
    /* last attribute */

struct debug_gen_key {
    uint32_t in_port;
#define DEBUG_GEN_ATTR(_name, _tlvname, _bitflag, _type, _defmask)      \
    _type _name; \
    /* end macro */
    DEBUG_GEN_ATTRS
#undef DEBUG_GEN_ATTR
    uint8_t ip_pkt; /* IPv4 or IPv6 */
    uint8_t pad[3];
};
AIM_STATIC_ASSERT(DEBUG_GEN_KEY_SIZE, sizeof(struct debug_gen_key) == 88);

struct debug_gen_value {
    struct span_group *span; /* NULL if unused */
    struct lag_group *lag; /* NULL if unused */
    bool cpu;
    bool drop;
};

struct debug_gen_entry {
    struct tcam_entry tcam_entry;
    struct debug_gen_value value;
    struct stats_handle stats_handle;
};

void pipeline_bvs_table_debug_gen_register(void);
void pipeline_bvs_table_debug_gen_unregister(void);
struct debug_gen_entry *pipeline_bvs_table_debug_gen_lookup(const struct debug_gen_key *key);

#endif
