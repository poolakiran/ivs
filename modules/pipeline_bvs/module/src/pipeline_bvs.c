/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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

#include "pipeline_bvs_support.h"
#include <murmur/murmur.h>

#define AIM_LOG_MODULE_NAME pipeline_bvs
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

enum table_id {
    TABLE_ID_L2 = 0,
    TABLE_ID_VLAN = 1,
    TABLE_ID_PORT = 2,
    TABLE_ID_VLAN_XLATE = 3,
    TABLE_ID_EGR_VLAN_XLATE = 4,
    TABLE_ID_MY_STATION = 5,
    TABLE_ID_L3_HOST_ROUTE = 6,
    TABLE_ID_L3_CIDR_ROUTE = 7,
    TABLE_ID_FLOOD = 11,
    TABLE_ID_ACL1 = 12,
    TABLE_ID_ACL2 = 13,
    TABLE_ID_ACL3 = 14,
    TABLE_ID_DEBUG = 15,
    TABLE_ID_INGRESS_MIRROR = 16,
    TABLE_ID_EGRESS_MIRROR = 17,
    TABLE_ID_VLAN_ACL = 19,
};

enum group_table_id {
    GROUP_TABLE_ID_LAG = 0,
    GROUP_TABLE_ID_ECMP = 1,
    GROUP_TABLE_ID_SPAN = 2,
};

static const bool flood_on_dlf = true;
static const of_mac_addr_t slow_protocols_mac = { { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 } };

static indigo_error_t process_l3( struct ind_ovs_cfr *cfr, uint32_t hash, uint32_t ingress_lag_id, bool disable_split_horizon_check, struct pipeline_result *result);
static void process_debug(struct ind_ovs_cfr *cfr, uint32_t hash, struct pipeline_result *result, bool *drop);
static indigo_error_t lookup_l2( uint16_t vlan_vid, const uint8_t *eth_addr, struct xbuf *stats, uint32_t *port_no, uint32_t *group_id);
static indigo_error_t check_vlan( uint16_t vlan_vid, uint32_t in_port, bool *tagged, uint32_t *vrf, bool *global_vrf_allowed);
static bool is_vlan_configured( uint16_t vlan_vid);
static indigo_error_t flood_vlan( uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash, struct pipeline_result *result);
static void mirror(uint8_t table_id, uint32_t port_no, uint32_t hash, struct pipeline_result *result);
static void span(uint32_t span_id, uint32_t hash, struct pipeline_result *result);
static indigo_error_t lookup_port( uint32_t port_no, uint16_t *default_vlan_vid, uint32_t *lag_id, bool *disable_src_mac_check, bool *arp_offload, bool *dhcp_offload, bool *disable_split_horizon_check);
static indigo_error_t lookup_vlan_xlate( uint32_t port_no, uint32_t lag_id, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate( uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t select_lag_port( uint32_t group_id, uint32_t hash, uint32_t *port_no);
static indigo_error_t select_ecmp_route(uint32_t group_id, uint32_t hash, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id);
static indigo_error_t lookup_my_station( const uint8_t *eth_addr);
static indigo_error_t lookup_l3_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, bool global_vrf_allowed, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap);
static indigo_error_t lookup_l3_host_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap);
static indigo_error_t lookup_l3_cidr_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap);
static void lookup_debug(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *span_id, bool *cpu, bool *drop);
static indigo_error_t lookup_vlan_acl(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *vrf, uint32_t *l3_interface_clas_id, of_mac_addr_t *vrouter_mac);
static uint32_t group_to_table_id(uint32_t group_id);

static void
pipeline_bvs_init(const char *name)
{
}

static void
pipeline_bvs_finish(void)
{
}

static indigo_error_t
pipeline_bvs_process(struct ind_ovs_parsed_key *key,
                     struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(key, &cfr);

    uint32_t hash = murmur_hash(&cfr, sizeof(cfr), 0);

    mirror(TABLE_ID_INGRESS_MIRROR, cfr.in_port, hash, result);

    if (cfr.dl_type == htons(0x88cc)) {
        AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(cfr.dl_type));
        pktin(result, OF_PACKET_IN_REASON_ACTION);
        return INDIGO_ERROR_NONE;
    }

    if (!memcmp(cfr.dl_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("sending slow protocols packet directly to controller");
        pktin(result, OF_PACKET_IN_REASON_ACTION);
        return INDIGO_ERROR_NONE;
    }

    uint16_t default_vlan_vid;
    uint32_t lag_id;
    bool disable_src_mac_check;
    bool arp_offload;
    bool dhcp_offload;
    bool disable_split_horizon_check;
    if (cfr.in_port == OF_PORT_DEST_LOCAL) {
        default_vlan_vid = 0;
        lag_id = OF_GROUP_ANY;
        disable_src_mac_check = true;
        arp_offload = false;
        dhcp_offload = false;
        disable_split_horizon_check = false;
    } else {
        if (lookup_port(cfr.in_port, &default_vlan_vid, &lag_id, &disable_src_mac_check, &arp_offload, &dhcp_offload, &disable_split_horizon_check) < 0) {
            AIM_LOG_WARN("port %u not found", cfr.in_port);
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_LOG_VERBOSE("hit in port table lookup, default_vlan_vid=%u lag_id=%u disable_src_mac_check=%u arp_offload=%u dhcp_offload=%u", default_vlan_vid, lag_id, disable_src_mac_check, arp_offload, dhcp_offload);

    uint16_t vlan_vid;
    if (cfr.dl_vlan & htons(VLAN_CFI_BIT)) {
        vlan_vid = VLAN_VID(ntohs(cfr.dl_vlan));
        uint16_t new_vlan_vid;
        if (lookup_vlan_xlate(cfr.in_port, lag_id, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    } else {
        vlan_vid = default_vlan_vid;
        push_vlan(result, 0x8100);
        set_vlan_vid(result, vlan_vid);
    }

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(ntohs(cfr.dl_vlan))) | VLAN_CFI_BIT);

    /* Generate packet-in if packet received on unconfigured VLAN */
    if (is_vlan_configured(vlan_vid) == false) {
        AIM_LOG_VERBOSE("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        pktin(result, OF_PACKET_IN_REASON_BSN_BAD_VLAN);
        return INDIGO_ERROR_NONE;
    }

    UNUSED bool in_port_tagged;
    bool global_vrf_allowed;
    uint32_t vrf;
    if (check_vlan(vlan_vid, cfr.in_port, &in_port_tagged, &vrf, &global_vrf_allowed) < 0) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", cfr.in_port, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("VLAN %u: vrf=%u global_vrf_allowed=%d", vlan_vid, vrf, global_vrf_allowed);
    cfr.vrf = vrf;
    cfr.global_vrf_allowed = global_vrf_allowed;

    uint32_t l3_interface_class_id;
    of_mac_addr_t vrouter_mac;
    if (lookup_vlan_acl(&cfr, &result->stats, &vrf, &l3_interface_class_id, &vrouter_mac) == 0) {
        AIM_LOG_VERBOSE("Hit in vlan_acl table: vrf=%u", vrf);
        cfr.vrf = vrf;
    }

    if (!disable_src_mac_check) {
        /* Source lookup */
        uint32_t src_port_no, src_group_id;
        if (lookup_l2(vlan_vid, cfr.dl_src, &result->stats, &src_port_no, &src_group_id) < 0) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            pktin(result, OF_PACKET_IN_REASON_BSN_NEW_HOST);
            return INDIGO_ERROR_NONE;
        }

        AIM_LOG_VERBOSE("hit in source l2table lookup, src_port_no=%u src_group_id=%u", src_port_no, src_group_id);

        if (src_port_no != OF_PORT_DEST_NONE && src_port_no != cfr.in_port) {
            AIM_LOG_VERBOSE("incorrect port in source l2table lookup (station move)");
            pktin(result, OF_PACKET_IN_REASON_BSN_STATION_MOVE);
            return INDIGO_ERROR_NONE;
        } else if (src_group_id != OF_GROUP_ANY && src_group_id != lag_id) {
            AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
            pktin(result, OF_PACKET_IN_REASON_BSN_STATION_MOVE);
            return INDIGO_ERROR_NONE;
        }
    }

    /* ARP offload */
    if (arp_offload) {
        if (cfr.dl_type == htons(0x0806)) {
            pktin(result, OF_PACKET_IN_REASON_BSN_ARP);
            /* Continue forwarding packet */
        }
    }

    /* DHCP offload */
    if (dhcp_offload) {
        if (cfr.dl_type == htons(0x0800) && cfr.nw_proto == 17 &&
                (cfr.tp_dst == htons(67) || cfr.tp_dst == htons(68))) {
            pktin(result, OF_PACKET_IN_REASON_BSN_DHCP);
            return INDIGO_ERROR_NONE;
        }
    }

    /* Check for broadcast/multicast */
    if (cfr.dl_dst[0] & 1) {
        bool drop;
        process_debug(&cfr, hash, result, &drop);
        if (drop) {
            return INDIGO_ERROR_NONE;
        }

        if (flood_vlan(vlan_vid, cfr.in_port, lag_id, hash, result) < 0) {
            AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }
        return INDIGO_ERROR_NONE;
    }

    if (lookup_my_station(cfr.dl_dst) == 0) {
        AIM_LOG_VERBOSE("hit in MyStation table, entering L3 processing");
        return process_l3(&cfr, hash, lag_id, disable_split_horizon_check, result);
    }

    /* Destination lookup */
    uint32_t dst_port_no, dst_group_id;
    if (lookup_l2(vlan_vid, cfr.dl_dst, NULL, &dst_port_no, &dst_group_id) < 0) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");

        bool drop;
        process_debug(&cfr, hash, result, &drop);
        if (drop) {
            return INDIGO_ERROR_NONE;
        }

        if (flood_on_dlf) {
            if (flood_vlan(vlan_vid, cfr.in_port, lag_id, hash, result) < 0) {
                AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
            }
        } else {
            pktin(result, OF_PACKET_IN_REASON_BSN_DESTINATION_LOOKUP_FAILURE);
        }
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in destination l2table lookup, dst_port_no=%u dst_group_id=%u", dst_port_no, dst_group_id);

    bool drop;
    process_debug(&cfr, hash, result, &drop);
    if (drop) {
        return INDIGO_ERROR_NONE;
    }

    if (dst_group_id != OF_GROUP_ANY) {
        if (select_lag_port(dst_group_id, hash, &dst_port_no) < 0) {
            return INDIGO_ERROR_NONE;
        }
        AIM_LOG_VERBOSE("selected LAG port %u", dst_port_no);
    }

    UNUSED uint16_t out_default_vlan_vid;
    uint32_t out_lag_id;
    UNUSED bool out_disable_src_mac_check;
    UNUSED bool out_arp_offload;
    UNUSED bool out_dhcp_offload;
    UNUSED bool out_disable_split_horizon_check;
    if (lookup_port(dst_port_no, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check, &out_arp_offload, &out_dhcp_offload, &out_disable_split_horizon_check) < 0) {
        AIM_LOG_WARN("port %u not found during egress", dst_port_no);
        return INDIGO_ERROR_NONE;
    }

    if (out_lag_id != OF_GROUP_ANY && out_lag_id == lag_id) {
        AIM_LOG_VERBOSE("skipping ingress LAG %u", lag_id);
        return INDIGO_ERROR_NONE;
    }

    bool out_port_tagged;
    UNUSED bool out_global_vrf_allowed;
    UNUSED uint32_t out_vrf;
    if (check_vlan(vlan_vid, dst_port_no, &out_port_tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
        AIM_LOG_WARN("output port %u not allowed on vlan %u", dst_port_no, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    if (!out_port_tagged) {
        pop_vlan(result);
    } else {
        uint16_t new_vlan_vid;
        if (lookup_egr_vlan_xlate(dst_port_no, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    }

    mirror(TABLE_ID_EGRESS_MIRROR, dst_port_no, hash, result);
    output(result, dst_port_no);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
process_l3(struct ind_ovs_cfr *cfr,
           uint32_t hash,
           uint32_t ingress_lag_id,
           bool disable_split_horizon_check,
           struct pipeline_result *result)
{
    of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
    uint16_t new_vlan_vid;
    uint32_t lag_id;
    bool trap = false;
    bool valid_next_hop = false;

    check_nw_ttl(result);

    if (lookup_l3_route(hash, cfr->vrf, cfr->nw_dst, cfr->global_vrf_allowed,
                        &new_eth_src, &new_eth_dst, &new_vlan_vid, &lag_id, &trap) == 0) {
        valid_next_hop = true;
    }

    bool drop;
    process_debug(cfr, hash, result, &drop);
    if (drop) {
        return INDIGO_ERROR_NONE;
    }

    if (trap) {
        AIM_LOG_VERBOSE("L3 trap to CPU");
        pktin(result, OF_PACKET_IN_REASON_ACTION);
        return INDIGO_ERROR_NONE;
    }

    if (!valid_next_hop) {
        AIM_LOG_VERBOSE("no route to host");
        pktin(result, OF_PACKET_IN_REASON_BSN_NO_ROUTE);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("next-hop: eth_src="FORMAT_MAC" eth_dst="FORMAT_MAC" vlan=%u lag_id=%u",
                    VALUE_MAC(new_eth_src.addr), VALUE_MAC(new_eth_dst.addr), new_vlan_vid, lag_id);

    uint32_t out_port;
    if (select_lag_port(lag_id, hash, &out_port) < 0) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", out_port);

    bool out_port_tagged;
    UNUSED bool out_global_vrf_allowed;
    UNUSED uint32_t out_vrf;
    if (check_vlan(new_vlan_vid, out_port, &out_port_tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
        AIM_LOG_WARN("output port %u not allowed on vlan %u", out_port, new_vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    if (!disable_split_horizon_check && lag_id == ingress_lag_id) {
        AIM_LOG_VERBOSE("skipping ingress LAG %u", lag_id);
        return INDIGO_ERROR_NONE;
    }

    if (!out_port_tagged) {
        pop_vlan(result);
    } else {
        lookup_egr_vlan_xlate(out_port, new_vlan_vid, &new_vlan_vid);
        set_vlan_vid(result, new_vlan_vid);
    }

    set_eth_src(result, new_eth_src);
    set_eth_dst(result, new_eth_dst);
    dec_nw_ttl(result);
    mirror(TABLE_ID_EGRESS_MIRROR, out_port, hash, result);
    output(result, out_port);
    return INDIGO_ERROR_NONE;
}

static void
process_debug(struct ind_ovs_cfr *cfr,
              uint32_t hash,
              struct pipeline_result *result,
              bool *drop)
{
    uint32_t span_id;
    bool cpu;

    lookup_debug(cfr, &result->stats, &span_id, &cpu, drop);

    if (span_id != OF_GROUP_ANY) {
        span(span_id, hash, result);
    }

    if (cpu) {
        pktin(result, OF_PACKET_IN_REASON_BSN_DEBUG);
    }
}

static indigo_error_t
lookup_l2(uint16_t vlan_vid, const uint8_t *eth_addr, struct xbuf *stats,
          uint32_t *port_no, uint32_t *group_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    *port_no = OF_PORT_DEST_NONE;
    *group_id = OF_GROUP_ANY;

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);
    memcpy(&cfr.dl_dst, eth_addr, sizeof(cfr.dl_dst));

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_L2, &cfr, stats);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            *port_no = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *group_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static bool
is_vlan_configured(uint16_t vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_VLAN, &cfr, NULL);
    if (effects != NULL) {
        return true;
    }

    return false;
}

static indigo_error_t
check_vlan(uint16_t vlan_vid, uint32_t in_port,
           bool *tagged, uint32_t *vrf, bool *global_vrf_allowed)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_VLAN, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *tagged = true;
    *vrf = 0;
    *global_vrf_allowed = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            uint32_t port_no = *XBUF_PAYLOAD(attr, uint32_t);
            if (port_no == in_port) {
                return INDIGO_ERROR_NONE;
            }
        } else if (attr->nla_type == IND_OVS_ACTION_POP_VLAN) {
            *tagged = false;
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VRF) {
            *vrf = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_GLOBAL_VRF_ALLOWED) {
            *global_vrf_allowed = *XBUF_PAYLOAD(attr, uint8_t);
        }
    }

    if (in_port == OF_PORT_DEST_LOCAL) {
        *tagged = true;
        return INDIGO_ERROR_NONE;
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
flood_vlan(uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash,
           struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.lag_id = lag_id;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_FLOOD, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    uint16_t tag = vlan_vid;
    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT ||
                attr->nla_type == IND_OVS_ACTION_GROUP) {
            uint32_t port_no;

            if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
                port_no = *XBUF_PAYLOAD(attr, uint32_t);
            } else {
                uint32_t group_id = *XBUF_PAYLOAD(attr, uint32_t);
                if (select_lag_port(group_id, hash, &port_no) < 0) {
                    AIM_LOG_VERBOSE("LAG %u is empty", group_id);
                    continue;
                }
                AIM_LOG_VERBOSE("selected LAG %u port %u", group_id, port_no);
            }

            bool tagged;
            UNUSED bool out_global_vrf_allowed;
            UNUSED uint32_t out_vrf;
            if (check_vlan(vlan_vid, port_no, &tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
                AIM_LOG_VERBOSE("not flooding vlan %u to port %u", vlan_vid, port_no);
                continue;
            }

            if (port_no == in_port) {
                AIM_LOG_VERBOSE("not flooding vlan %u to ingress port %u", vlan_vid, port_no);
                continue;
            }

            uint16_t out_default_vlan_vid;
            uint32_t out_lag_id;
            bool out_disable_src_mac_check;
            bool out_arp_offload;
            bool out_dhcp_offload;
            bool out_disable_split_horizon_check;
            if (lookup_port(port_no, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check, &out_arp_offload, &out_dhcp_offload, &out_disable_split_horizon_check) < 0) {
                AIM_LOG_WARN("port %u not found during flood", port_no);
                continue;
            }

            if (out_lag_id != OF_GROUP_ANY && out_lag_id == lag_id) {
                AIM_LOG_VERBOSE("skipping ingress LAG %u", lag_id);
                continue;
            }

            uint16_t new_tag;
            if (tagged) {
                if (lookup_egr_vlan_xlate(port_no, vlan_vid, &new_tag) < 0) {
                    new_tag = vlan_vid;
                }
            } else {
                new_tag = 0;
            }

            if (new_tag != tag) {
                if (new_tag == 0) {
                    pop_vlan(result);
                } else {
                    if (tag == 0) {
                        push_vlan(result, 0x8100);
                    }
                    set_vlan_vid(result, new_tag);
                }
                tag = new_tag;
            }

            mirror(TABLE_ID_EGRESS_MIRROR, port_no, hash, result);
            output(result, port_no);
        }
    }

    return INDIGO_ERROR_NONE;
}

static void
mirror(uint8_t table_id, uint32_t port_no, uint32_t hash,
       struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(table_id, &cfr, NULL);
    if (effects == NULL) {
        return;
    }

    AIM_LOG_VERBOSE("Hit in mirror table for port %d", port_no);

    uint32_t span_group_id = OF_GROUP_ANY;
    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            span_group_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    if (span_group_id == OF_GROUP_ANY) {
        AIM_LOG_ERROR("No span group action");
        return;
    }

    span(span_group_id, hash, result);
}

static void
span(uint32_t span_id, uint32_t hash, struct pipeline_result *result)
{
    struct xbuf *span_actions;
    if (ind_ovs_group_indirect(span_id, &span_actions) < 0) {
        AIM_LOG_ERROR("Failed to lookup span group %#x", span_id);
        return;
    }

    uint32_t dst_group_id = OF_GROUP_ANY;
    struct nlattr *attr;
    XBUF_FOREACH2(span_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            dst_group_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    if (dst_group_id == OF_GROUP_ANY) {
        AIM_LOG_ERROR("No LAG group action");
        return;
    }

    uint32_t dst_port_no;
    if (select_lag_port(dst_group_id, hash, &dst_port_no) < 0) {
        return;
    }
    AIM_LOG_VERBOSE("Selected LAG port %u", dst_port_no);

    output(result, dst_port_no);
}

static indigo_error_t
lookup_port(uint32_t port_no,
            uint16_t *default_vlan_vid, uint32_t *lag_id,
            bool *disable_src_mac_check, bool *arp_offload, bool *dhcp_offload, bool *disable_split_horizon_check)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    *default_vlan_vid = 0;
    *lag_id = OF_GROUP_ANY;
    *disable_src_mac_check = false;
    *arp_offload = false;
    *dhcp_offload = false;
    *disable_split_horizon_check = false;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_PORT, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *default_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_LAG_ID) {
            *lag_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    *disable_src_mac_check = effects->disable_src_mac_check;
    *arp_offload = effects->arp_offload;
    *dhcp_offload = effects->dhcp_offload;
    *disable_split_horizon_check = effects->disable_split_horizon_check;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_vlan_xlate(uint32_t port_no, uint32_t lag_id, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.lag_id = lag_id;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_VLAN_XLATE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
lookup_egr_vlan_xlate(uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_EGR_VLAN_XLATE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
select_lag_port(uint32_t group_id, uint32_t hash, uint32_t *port_no)
{
    indigo_error_t rv;

    struct xbuf *actions;
    rv = ind_ovs_group_select(group_id, hash, &actions);
    if (rv < 0) {
        AIM_LOG_WARN("error selecting LAG group %u bucket: %s", group_id, indigo_strerror(rv));
        return rv;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            *port_no = *XBUF_PAYLOAD(attr, uint32_t);
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_LOG_WARN("no output action found in group %u bucket", group_id);
    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
select_ecmp_route(
    uint32_t group_id, uint32_t hash,
    of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
    uint16_t *new_vlan_vid, uint32_t *lag_id)
{
    indigo_error_t rv;

    struct xbuf *actions;
    rv = ind_ovs_group_select(group_id, hash, &actions);
    if (rv < 0) {
        AIM_LOG_WARN("error selecting ECMP group %u bucket: %s", group_id, indigo_strerror(rv));
        return rv;
    }

    *lag_id = OF_GROUP_ANY;
    memset(new_eth_src, 0, sizeof(*new_eth_src));
    memset(new_eth_dst, 0, sizeof(*new_eth_dst));
    *new_vlan_vid = 0;

    struct nlattr *attr;
    XBUF_FOREACH2(actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *lag_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_my_station(const uint8_t *eth_addr)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    memcpy(&cfr.dl_dst, eth_addr, sizeof(cfr.dl_dst));

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_MY_STATION, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l3_route(uint32_t hash,
                uint32_t vrf, uint32_t ipv4_dst, bool global_vrf_allowed,
                of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap)
{
    indigo_error_t ret;

    AIM_LOG_VERBOSE("looking up route for VRF=%u ip="FORMAT_IPV4" global_vrf_allowed=%u",
                    vrf, VALUE_IPV4((uint8_t *)&ipv4_dst), global_vrf_allowed);

    if ((ret = lookup_l3_host_route(
        hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id, trap)) == 0) {
        AIM_LOG_VERBOSE("hit in host route table");
        return INDIGO_ERROR_NONE;
    }

    if ((ret = lookup_l3_cidr_route(
        hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id, trap)) == 0) {
        AIM_LOG_VERBOSE("hit in CIDR route table");
        return INDIGO_ERROR_NONE;
    }

    if (global_vrf_allowed) {
        if ((ret = lookup_l3_host_route(
            hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id, trap)) == 0) {
            AIM_LOG_VERBOSE("hit in global host route table");
            return INDIGO_ERROR_NONE;
        }

        if ((ret = lookup_l3_cidr_route(
            hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id, trap)) == 0) {
            AIM_LOG_VERBOSE("hit in global CIDR route table");
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
lookup_l3_host_route(uint32_t hash,
                     uint32_t vrf, uint32_t ipv4_dst,
                     of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                     uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_type = htons(0x0800);
    cfr.vrf = vrf;
    cfr.nw_dst = ipv4_dst;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_L3_HOST_ROUTE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    uint32_t group_id = OF_GROUP_ANY;
    memset(new_eth_src, 0, sizeof(*new_eth_src));
    memset(new_eth_dst, 0, sizeof(*new_eth_dst));
    *new_vlan_vid = 0;
    *trap = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            group_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *trap = true;
        }
    }

    if (group_id != OF_GROUP_ANY) {
        switch (group_to_table_id(group_id)) {
        case GROUP_TABLE_ID_LAG:
            *lag_id = group_id;
            break;
        case GROUP_TABLE_ID_ECMP:
            if (select_ecmp_route(group_id, hash, new_eth_src, new_eth_dst, new_vlan_vid, lag_id) < 0) {
                return INDIGO_ERROR_NOT_FOUND;
            }
            break;
        default:
            return INDIGO_ERROR_COMPAT;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l3_cidr_route(uint32_t hash,
                     uint32_t vrf, uint32_t ipv4_dst,
                     of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                     uint16_t *new_vlan_vid, uint32_t *lag_id, bool *trap)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_type = htons(0x0800);
    cfr.vrf = vrf;
    cfr.nw_dst = ipv4_dst;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_L3_CIDR_ROUTE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    uint32_t group_id = OF_GROUP_ANY;
    memset(new_eth_src, 0, sizeof(*new_eth_src));
    memset(new_eth_dst, 0, sizeof(*new_eth_dst));
    *new_vlan_vid = 0;
    *trap = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            group_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *trap = true;
        }
    }

    if (group_id != OF_GROUP_ANY) {
        switch (group_to_table_id(group_id)) {
        case GROUP_TABLE_ID_LAG:
            *lag_id = group_id;
            break;
        case GROUP_TABLE_ID_ECMP:
            if (select_ecmp_route(group_id, hash, new_eth_src, new_eth_dst, new_vlan_vid, lag_id) < 0) {
                return INDIGO_ERROR_NOT_FOUND;
            }
            break;
        default:
            return INDIGO_ERROR_COMPAT;
        }
    }

    return INDIGO_ERROR_NONE;
}

static void
lookup_debug(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *span_id, bool *cpu, bool *drop)
{
    *span_id = OF_GROUP_ANY;
    *cpu = false;
    *drop = false;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_DEBUG, cfr, stats);
    if (effects == NULL) {
        return;
    }

    *drop = effects->deny;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *span_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *cpu = true;
        }
    }

    AIM_LOG_VERBOSE("hit in debug table: span_id=0x%x cpu=%d drop=%d", *span_id, *cpu, *drop);
}

static indigo_error_t
lookup_vlan_acl(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *vrf, uint32_t *l3_interface_class_id, of_mac_addr_t *vrouter_mac)
{
    *vrf = 0;
    *l3_interface_class_id = 0;
    memset(vrouter_mac, 0, sizeof(*vrouter_mac));

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_VLAN_ACL, cfr, stats);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VRF) {
            *vrf = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_L3_INTERFACE_CLASS_ID) {
            *l3_interface_class_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(vrouter_mac->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        }
    }

    return INDIGO_ERROR_NONE;
}

static uint32_t
group_to_table_id(uint32_t group_id)
{
    return group_id >> 24;
}

static struct pipeline_ops pipeline_bvs_ops = {
    .init = pipeline_bvs_init,
    .finish = pipeline_bvs_finish,
    .process = pipeline_bvs_process,
};

void
__pipeline_bvs_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("bvs-1.0", &pipeline_bvs_ops);
    pipeline_register("experimental", &pipeline_bvs_ops); /* For command-line compatibility */
}
