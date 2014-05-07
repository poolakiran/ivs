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

#include "pipeline_bvs_int.h"
#include <murmur/murmur.h>
#include <indigo/of_connection_manager.h>

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
    TABLE_ID_INGRESS_ACL = 12,
    TABLE_ID_DEBUG = 15,
    TABLE_ID_INGRESS_MIRROR = 16,
    TABLE_ID_EGRESS_MIRROR = 17,
    TABLE_ID_EGRESS_ACL = 18,
    TABLE_ID_VLAN_ACL = 19,
};

enum group_table_id {
    GROUP_TABLE_ID_LAG = 0,
    GROUP_TABLE_ID_ECMP = 1,
    GROUP_TABLE_ID_SPAN = 2,
};

struct ctx {
    bool drop;
    bool pktin_agent;
    bool pktin_controller;
    uint64_t pktin_metadata;
};

static const bool flood_on_dlf = true;
static const of_mac_addr_t slow_protocols_mac = { { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 } };
static const of_mac_addr_t packet_of_death_mac = { { 0x5C, 0x16, 0xC7, 0xFF, 0xFF, 0x04 } };

static indigo_error_t process_l3( struct ind_ovs_cfr *cfr, uint32_t hash, uint32_t ingress_lag_id, of_mac_addr_t vrouter_mac, uint16_t orig_vlan_vid, uint8_t ttl, struct pipeline_result *result, struct ctx *ctx);
static void process_debug(struct ind_ovs_cfr *cfr, uint32_t hash, uint16_t orig_vlan_vid, struct pipeline_result *result, struct ctx *ctx);
static indigo_error_t lookup_l2( uint16_t vlan_vid, const uint8_t *eth_addr, struct xbuf *stats, uint32_t *port_no, uint32_t *group_id);
static indigo_error_t check_vlan( uint16_t vlan_vid, uint32_t in_port, bool *tagged, uint32_t *vrf, bool *global_vrf_allowed, uint32_t *l3_interface_class_id, of_mac_addr_t *vrouter_mac);
static bool is_vlan_configured( uint16_t vlan_vid);
static indigo_error_t flood_vlan( uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash, struct pipeline_result *result);
static void mirror(uint8_t table_id, uint32_t port_no, uint32_t hash, struct pipeline_result *result);
static void span(uint32_t span_id, uint32_t hash, struct pipeline_result *result);
static indigo_error_t lookup_port( uint32_t port_no, uint16_t *default_vlan_vid, uint32_t *lag_id, bool *disable_src_mac_check, bool *arp_offload, bool *dhcp_offload, bool *allow_packet_of_death, uint32_t *egr_port_group_id);
static indigo_error_t lookup_vlan_xlate( uint32_t port_no, uint32_t lag_id, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate( uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t select_lag_port( uint32_t group_id, uint32_t hash, uint32_t *port_no);
static indigo_error_t select_ecmp_route(uint32_t group_id, uint32_t hash, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id);
static indigo_error_t lookup_my_station( const uint8_t *eth_addr);
static indigo_error_t lookup_l3_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, bool global_vrf_allowed, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *valid_next_hop, bool *valid_cpu, bool *hit);
static indigo_error_t lookup_l3_host_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *valid_next_hop, bool *valid_cpu);
static indigo_error_t lookup_l3_cidr_route( uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *valid_next_hop, bool *valid_cpu);
static void lookup_debug(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *span_id, bool *cpu, bool *drop);
static indigo_error_t lookup_vlan_acl(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *vrf, uint32_t *l3_interface_clas_id, uint32_t *l3_src_class_id, of_mac_addr_t *vrouter_mac);
static void lookup_ingress_acl(struct ind_ovs_cfr *cfr, uint32_t hash, struct xbuf *stats, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *lag_id, bool *valid_next_hop, bool *cpu, bool *drop, bool *hit);
static void lookup_egress_acl(struct ind_ovs_cfr *cfr, bool *drop);
static uint32_t group_to_table_id(uint32_t group_id);
static void mark_pktin_agent(struct ctx *ctx, uint64_t flag);
static void mark_pktin_controller(struct ctx *ctx, uint64_t flag);
static void mark_drop(struct ctx *ctx);
static void process_pktin(struct ctx *ctx, struct pipeline_result *result);

/*
 * Switch -> Controller async msg channel selector.
 *
 * For now all the async msgs (packet-in, lacp, lldp, etc.)
 * go on aux 1, if present, else on main channel.
 * Note - This might change as requirements change
 */
static void
pipeline_bvs_cxn_async_channel_selector(const of_object_t *obj, uint32_t num_aux,
                                        uint8_t *auxiliary_id)
{
    AIM_ASSERT(auxiliary_id != NULL);

    if (num_aux == 0) {
        *auxiliary_id = 0;
    } else {
        *auxiliary_id = 1;
    }
}

static void
pipeline_bvs_init(const char *name)
{
    indigo_cxn_async_channel_selector_register(pipeline_bvs_cxn_async_channel_selector);
}

static void
pipeline_bvs_finish(void)
{
    indigo_cxn_async_channel_selector_unregister(pipeline_bvs_cxn_async_channel_selector);
}

static indigo_error_t
pipeline_bvs_process(struct ind_ovs_parsed_key *key,
                     struct pipeline_result *result)
{
    struct ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(key, &cfr);

    uint32_t hash = murmur_hash(&cfr, sizeof(cfr), 0);
    uint16_t orig_vlan_vid = VLAN_VID(ntohs(cfr.dl_vlan));

    mirror(TABLE_ID_INGRESS_MIRROR, cfr.in_port, hash, result);

    bool packet_of_death = false;
    if (cfr.dl_type == htons(0x88cc)) {
        if (!memcmp(cfr.dl_src, packet_of_death_mac.addr, OF_MAC_ADDR_BYTES)) {
            packet_of_death = true;
        } else {
            AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(cfr.dl_type));
            mark_pktin_agent(&ctx, OFP_BSN_PKTIN_FLAG_PDU);
            mark_drop(&ctx);
        }
    }

    if (!memcmp(cfr.dl_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("sending slow protocols packet directly to controller");
        mark_pktin_agent(&ctx, OFP_BSN_PKTIN_FLAG_PDU);
        mark_drop(&ctx);
    }

    /* HACK early drop for PDUs */
    if (ctx.drop) {
        process_pktin(&ctx, result);
        return INDIGO_ERROR_NONE;
    }

    uint16_t default_vlan_vid;
    uint32_t lag_id;
    bool disable_src_mac_check;
    bool arp_offload;
    bool dhcp_offload;
    bool allow_packet_of_death;
    uint32_t egr_port_group_id;
    if (cfr.in_port == OF_PORT_DEST_LOCAL) {
        default_vlan_vid = 0;
        lag_id = OF_GROUP_ANY;
        disable_src_mac_check = true;
        arp_offload = false;
        dhcp_offload = false;
        allow_packet_of_death = false;
        egr_port_group_id = 0;
    } else {
        if (lookup_port(cfr.in_port, &default_vlan_vid, &lag_id, &disable_src_mac_check, &arp_offload, &dhcp_offload, &allow_packet_of_death, &egr_port_group_id) < 0) {
            AIM_LOG_WARN("port %u not found", cfr.in_port);
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_LOG_VERBOSE("hit in port table lookup, default_vlan_vid=%u lag_id=%u disable_src_mac_check=%u arp_offload=%u dhcp_offload=%u allow_packet_of_death=%u", default_vlan_vid, lag_id, disable_src_mac_check, arp_offload, dhcp_offload, allow_packet_of_death);

    if (packet_of_death) {
        if (allow_packet_of_death) {
            AIM_LOG_VERBOSE("sending packet of death to cpu");
            pktin(result, OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, 0);
        } else {
            AIM_LOG_VERBOSE("ignoring packet of death on not-allowed port");
        }
        return INDIGO_ERROR_NONE;
    }

    uint32_t vrf;
    uint32_t l3_interface_class_id;
    uint32_t l3_src_class_id;
    of_mac_addr_t vrouter_mac;
    bool vlan_acl_hit = false;
    uint16_t vlan_vid = 0;
    if (lookup_vlan_acl(&cfr, &result->stats, &vrf, &l3_interface_class_id, &l3_src_class_id, &vrouter_mac) == 0) {
        AIM_LOG_VERBOSE("Hit in vlan_acl table: vrf=%u l3_interface_class_id=%u l3_src_class_id=%u", vrf, l3_interface_class_id, l3_src_class_id);
        cfr.vrf = vrf;
        cfr.l3_interface_class_id = l3_interface_class_id;
        cfr.l3_src_class_id = l3_src_class_id;
        vlan_vid = VLAN_VID(ntohs(cfr.dl_vlan));
        vlan_acl_hit = true;
    } else {
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
    }

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(ntohs(cfr.dl_vlan))) | VLAN_CFI_BIT);

    if (is_vlan_configured(vlan_vid) == false) {
        AIM_LOG_VERBOSE("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        mark_drop(&ctx);
        return INDIGO_ERROR_NONE;
    }

    UNUSED bool in_port_tagged;
    bool global_vrf_allowed;
    uint32_t vlan_l3_interface_class_id;
    of_mac_addr_t vlan_vrouter_mac;
    if (check_vlan(vlan_vid, cfr.in_port, &in_port_tagged, &vrf, &global_vrf_allowed, &vlan_l3_interface_class_id, &vlan_vrouter_mac) < 0) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", cfr.in_port, vlan_vid);
        mark_drop(&ctx);
        return INDIGO_ERROR_NONE;
    }

    if (!vlan_acl_hit) {
        AIM_LOG_VERBOSE("VLAN %u: vrf=%u global_vrf_allowed=%d", vlan_vid, vrf, global_vrf_allowed);
        cfr.vrf = vrf;
        cfr.global_vrf_allowed = global_vrf_allowed;
        cfr.l3_interface_class_id = vlan_l3_interface_class_id;
        memcpy(vrouter_mac.addr, vlan_vrouter_mac.addr, OF_MAC_ADDR_BYTES);
    }

    if (!disable_src_mac_check) {
        /* Source lookup */
        uint32_t src_port_no, src_group_id;
        if (lookup_l2(vlan_vid, cfr.dl_src, &result->stats, &src_port_no, &src_group_id) < 0) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            mark_pktin_controller(&ctx, OFP_BSN_PKTIN_FLAG_NEW_HOST);
            mark_drop(&ctx);
        }

        AIM_LOG_VERBOSE("hit in source l2table lookup, src_port_no=%u src_group_id=%u", src_port_no, src_group_id);

        if (src_port_no != OF_PORT_DEST_NONE && src_port_no != cfr.in_port) {
            AIM_LOG_VERBOSE("incorrect port in source l2table lookup (station move)");
            mark_pktin_controller(&ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE);
            mark_drop(&ctx);
        } else if (src_group_id != OF_GROUP_ANY && src_group_id != lag_id) {
            AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
            mark_pktin_controller(&ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE);
            mark_drop(&ctx);
        }
    }

    /* ARP offload */
    if (arp_offload) {
        if (cfr.dl_type == htons(0x0806)) {
            AIM_LOG_VERBOSE("sending ARP packet to agent");
            mark_pktin_agent(&ctx, OFP_BSN_PKTIN_FLAG_ARP);
            /* Continue forwarding packet */
        }
    }

    /* DHCP offload */
    if (dhcp_offload) {
        if (cfr.dl_type == htons(0x0800) && cfr.nw_proto == 17 &&
                (cfr.tp_dst == htons(67) || cfr.tp_dst == htons(68))) {
            AIM_LOG_VERBOSE("sending DHCP packet to agent");
            mark_pktin_agent(&ctx, OFP_BSN_PKTIN_FLAG_DHCP);
            mark_drop(&ctx);
        }
    }

    /* Check for broadcast/multicast */
    if (cfr.dl_dst[0] & 1) {
        process_debug(&cfr, hash, orig_vlan_vid, result, &ctx);
        process_pktin(&ctx, result);

        if (ctx.drop) {
            return INDIGO_ERROR_NONE;
        }

        if (flood_vlan(vlan_vid, cfr.in_port, lag_id, hash, result) < 0) {
            AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }

        return INDIGO_ERROR_NONE;
    }

    if (lookup_my_station(cfr.dl_dst) == 0) {
        AIM_LOG_VERBOSE("hit in MyStation table, entering L3 processing");
        return process_l3(&cfr, hash, lag_id, vrouter_mac, orig_vlan_vid, key->ipv4.ipv4_ttl, result, &ctx);
    }

    /* Destination lookup */
    uint32_t dst_port_no, dst_group_id;
    if (lookup_l2(vlan_vid, cfr.dl_dst, NULL, &dst_port_no, &dst_group_id) < 0) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");

        process_debug(&cfr, hash, orig_vlan_vid, result, &ctx);
        process_pktin(&ctx, result);

        if (ctx.drop) {
            return INDIGO_ERROR_NONE;
        }

        if (flood_on_dlf) {
            if (flood_vlan(vlan_vid, cfr.in_port, lag_id, hash, result) < 0) {
                AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
            }
        } else {
            /* not implemented */
        }
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in destination l2table lookup, dst_port_no=%u dst_group_id=%u", dst_port_no, dst_group_id);

    process_debug(&cfr, hash, orig_vlan_vid, result, &ctx);
    process_pktin(&ctx, result);

    if (ctx.drop) {
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
    UNUSED bool out_allow_packet_of_death;
    UNUSED uint32_t out_egr_port_group_id;
    if (lookup_port(dst_port_no, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check, &out_arp_offload, &out_dhcp_offload, &out_allow_packet_of_death, &egr_port_group_id) < 0) {
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
    UNUSED uint32_t out_l3_interface_class_id;
    UNUSED of_mac_addr_t out_vrouter_mac;
    if (check_vlan(vlan_vid, dst_port_no, &out_port_tagged, &out_vrf, &out_global_vrf_allowed, &out_l3_interface_class_id, &out_vrouter_mac) < 0) {
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
           of_mac_addr_t vrouter_mac,
           uint16_t orig_vlan_vid,
           uint8_t ttl,
           struct pipeline_result *result,
           struct ctx *ctx)
{
    UNUSED of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
    uint16_t new_vlan_vid;
    uint32_t lag_id;
    bool cpu;
    bool valid_next_hop;
    bool drop = false;
    bool hit = false;

    if (ttl <= 1) {
        AIM_LOG_VERBOSE("sending TTL expired packet to agent");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_TTL_EXPIRED);
        mark_drop(ctx);
    }

    lookup_l3_route(hash, cfr->vrf, cfr->nw_dst, cfr->global_vrf_allowed,
                    &new_eth_src, &new_eth_dst, &new_vlan_vid, &lag_id,
                    &valid_next_hop, &cpu, &hit);

    process_debug(cfr, hash, orig_vlan_vid, result, ctx);

    lookup_ingress_acl(cfr, hash, &result->stats, &new_eth_src, &new_eth_dst, &new_vlan_vid, &lag_id, &valid_next_hop, &cpu, &drop, &hit);

    if (cpu) {
        AIM_LOG_VERBOSE("L3 copy to CPU");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_CPU);

        if (drop) {
            AIM_LOG_VERBOSE("L3 drop");
            mark_drop(ctx);
        } else if (!valid_next_hop) {
            AIM_LOG_VERBOSE("L3 null route");
            mark_drop(ctx);
        }
    } else {
        if (drop) {
            AIM_LOG_VERBOSE("L3 drop");
            mark_drop(ctx);
        } else if (!hit) {
            AIM_LOG_VERBOSE("L3 miss");
            mark_drop(ctx);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_MISS);
        } else if (!valid_next_hop) {
            AIM_LOG_VERBOSE("L3 null route");
            mark_drop(ctx);
        }
    }

    process_pktin(ctx, result);

    if (ctx->drop) {
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
    UNUSED uint32_t out_l3_interface_class_id;
    UNUSED of_mac_addr_t out_vrouter_mac;
    if (check_vlan(new_vlan_vid, out_port, &out_port_tagged, &out_vrf, &out_global_vrf_allowed, &out_l3_interface_class_id, &out_vrouter_mac) < 0) {
        AIM_LOG_WARN("output port %u not allowed on vlan %u", out_port, new_vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    UNUSED uint16_t out_default_vlan_vid;
    uint32_t out_lag_id;
    UNUSED bool out_disable_src_mac_check;
    UNUSED bool out_arp_offload;
    UNUSED bool out_dhcp_offload;
    UNUSED bool out_allow_packet_of_death;
    uint32_t out_egr_port_group_id;
    if (lookup_port(out_port, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check, &out_arp_offload, &out_dhcp_offload, &out_allow_packet_of_death, &out_egr_port_group_id) < 0) {
        AIM_LOG_WARN("port %u not found during egress", out_port);
        return INDIGO_ERROR_NONE;
    }

    cfr->egr_port_group_id = out_egr_port_group_id;

    if (!out_port_tagged) {
        pop_vlan(result);
        cfr->dl_vlan = 0;
    } else {
        lookup_egr_vlan_xlate(out_port, new_vlan_vid, &new_vlan_vid);
        set_vlan_vid(result, new_vlan_vid);
        cfr->dl_vlan = htons(VLAN_TCI(new_vlan_vid, VLAN_PCP(ntohs(cfr->dl_vlan))) | VLAN_CFI_BIT);
    }

    lookup_egress_acl(cfr, &drop);
    if (drop) {
        return INDIGO_ERROR_NONE;
    }

    if (memcmp(&vrouter_mac.addr, of_mac_addr_all_zeros.addr, OF_MAC_ADDR_BYTES)) {
        set_eth_src(result, vrouter_mac);
    } else {
        set_eth_src(result, new_eth_src);
    }
    set_eth_dst(result, new_eth_dst);
    dec_nw_ttl(result);
    mirror(TABLE_ID_EGRESS_MIRROR, out_port, hash, result);
    output(result, out_port);
    return INDIGO_ERROR_NONE;
}

static void
process_debug(struct ind_ovs_cfr *cfr,
              uint32_t hash,
              uint16_t orig_vlan_vid,
              struct pipeline_result *result,
              struct ctx *ctx)
{
    uint32_t span_id;
    bool cpu, drop;

    lookup_debug(cfr, &result->stats, &span_id, &cpu, &drop);

    if (span_id != OF_GROUP_ANY) {
        set_vlan_vid(result, orig_vlan_vid);
        span(span_id, hash, result);
        set_vlan_vid(result, VLAN_VID(ntohs(cfr->dl_vlan)));
    }

    if (cpu) {
        mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_DEBUG);
    }

    if (drop) {
        mark_drop(ctx);
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
           bool *tagged, uint32_t *vrf, bool *global_vrf_allowed,
           uint32_t *l3_interface_class_id, of_mac_addr_t *vrouter_mac)
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
    *l3_interface_class_id = 0;
    memset(vrouter_mac, 0, sizeof(*vrouter_mac));

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
        } else if (attr->nla_type == IND_OVS_ACTION_SET_L3_INTERFACE_CLASS_ID) {
            *l3_interface_class_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(vrouter_mac->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
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
            UNUSED uint32_t out_l3_interface_class_id;
            UNUSED of_mac_addr_t out_vrouter_mac;
            if (check_vlan(vlan_vid, port_no, &tagged, &out_vrf, &out_global_vrf_allowed, &out_l3_interface_class_id, &out_vrouter_mac) < 0) {
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
            bool out_allow_packet_of_death;
            UNUSED uint32_t out_egr_port_group_id;
            if (lookup_port(port_no, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check, &out_arp_offload, &out_dhcp_offload, &out_allow_packet_of_death, &out_egr_port_group_id) < 0) {
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
            bool *disable_src_mac_check, bool *arp_offload, bool *dhcp_offload,
            bool *allow_packet_of_death,
            uint32_t *egr_port_group_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    *default_vlan_vid = 0;
    *lag_id = OF_GROUP_ANY;
    *disable_src_mac_check = false;
    *arp_offload = false;
    *dhcp_offload = false;
    *allow_packet_of_death = false;
    *egr_port_group_id = 0;

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
        } else if (attr->nla_type == IND_OVS_ACTION_SET_EGR_PORT_GROUP_ID) {
            *egr_port_group_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    *disable_src_mac_check = effects->disable_src_mac_check;
    *arp_offload = effects->arp_offload;
    *dhcp_offload = effects->dhcp_offload;
    *allow_packet_of_death = effects->packet_of_death;

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
                uint16_t *new_vlan_vid, uint32_t *lag_id,
                bool *valid_next_hop, bool *cpu, bool *hit)
{
    indigo_error_t ret;

    AIM_LOG_VERBOSE("looking up route for VRF=%u ip="FORMAT_IPV4" global_vrf_allowed=%u",
                    vrf, VALUE_IPV4((uint8_t *)&ipv4_dst), global_vrf_allowed);

    *valid_next_hop = false;
    *cpu = false;

    if ((ret = lookup_l3_host_route(
        hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id, valid_next_hop, cpu)) == 0) {
        AIM_LOG_VERBOSE("hit in host route table");
        *hit = true;
        return INDIGO_ERROR_NONE;
    }

    if ((ret = lookup_l3_cidr_route(
        hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id, valid_next_hop, cpu)) == 0) {
        AIM_LOG_VERBOSE("hit in CIDR route table");
        *hit = true;
        return INDIGO_ERROR_NONE;
    }

    if (global_vrf_allowed) {
        if ((ret = lookup_l3_host_route(
            hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id, valid_next_hop, cpu)) == 0) {
            AIM_LOG_VERBOSE("hit in global host route table");
            *hit = true;
            return INDIGO_ERROR_NONE;
        }

        if ((ret = lookup_l3_cidr_route(
            hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id, valid_next_hop, cpu)) == 0) {
            AIM_LOG_VERBOSE("hit in global CIDR route table");
            *hit = true;
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
lookup_l3_host_route(uint32_t hash,
                     uint32_t vrf, uint32_t ipv4_dst,
                     of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                     uint16_t *new_vlan_vid, uint32_t *lag_id,
                     bool *valid_next_hop, bool *cpu)
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
    *valid_next_hop = false;
    *cpu = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            group_id = *XBUF_PAYLOAD(attr, uint32_t);
            *valid_next_hop = true;
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *cpu = true;
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
                     uint16_t *new_vlan_vid, uint32_t *lag_id,
                     bool *valid_next_hop, bool *cpu)
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
    *valid_next_hop = false;
    *cpu = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            group_id = *XBUF_PAYLOAD(attr, uint32_t);
            *valid_next_hop = true;
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *cpu = true;
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
lookup_vlan_acl(struct ind_ovs_cfr *cfr, struct xbuf *stats, uint32_t *vrf, uint32_t *l3_interface_class_id, uint32_t *l3_src_class_id, of_mac_addr_t *vrouter_mac)
{
    *vrf = 0;
    *l3_interface_class_id = 0;
    *l3_src_class_id = 0;
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
        } else if (attr->nla_type == IND_OVS_ACTION_SET_L3_SRC_CLASS_ID) {
            *l3_src_class_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(vrouter_mac->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        }
    }

    return INDIGO_ERROR_NONE;
}

static void
lookup_ingress_acl(struct ind_ovs_cfr *cfr, uint32_t hash, struct xbuf *stats,
                   of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                   uint16_t *new_vlan_vid, uint32_t *lag_id,
                   bool *valid_next_hop, bool *cpu, bool *drop, bool *hit)
{
    /* Assumes return value memory is initialized */

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_INGRESS_ACL, cfr, stats);
    if (effects == NULL) {
        return;
    }

    AIM_LOG_VERBOSE("hit in ingress_acl table drop=%d", effects->deny);
    *hit = true;

    if (effects->deny) {
        *drop = effects->deny;
    }

    struct nlattr *attr;
    uint32_t group_id = OF_GROUP_ANY;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            group_id = *XBUF_PAYLOAD(attr, uint32_t);
            *valid_next_hop = true;
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_CONTROLLER) {
            *cpu = true;
        }
    }

    if (group_id != OF_GROUP_ANY) {
        switch (group_to_table_id(group_id)) {
        case GROUP_TABLE_ID_LAG:
            *lag_id = group_id;
            break;
        case GROUP_TABLE_ID_ECMP:
            if (select_ecmp_route(group_id, hash, new_eth_src, new_eth_dst, new_vlan_vid, lag_id) < 0) {
                AIM_LOG_ERROR("failed to get ecmp route from ingress_acl action");
                return;
            }
            break;
        default:
            AIM_LOG_ERROR("unexpected group table in ingress_acl action");
        }
    }
}

static void
lookup_egress_acl(struct ind_ovs_cfr *cfr, bool *drop)
{
    *drop = false;

    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID_EGRESS_ACL, cfr, NULL);
    if (effects == NULL) {
        return;
    }

    *drop = effects->deny;

    AIM_LOG_VERBOSE("hit in egress_acl table: drop=%d", *drop);
}

static uint32_t
group_to_table_id(uint32_t group_id)
{
    return group_id >> 24;
}

static void
mark_pktin_agent(struct ctx *ctx, uint64_t flag)
{
    ctx->pktin_agent = true;
    ctx->pktin_metadata |= flag;
}

static void
mark_pktin_controller(struct ctx *ctx, uint64_t flag)
{
    ctx->pktin_controller = true;
    ctx->pktin_metadata |= flag;
}

static void
mark_drop(struct ctx *ctx)
{
    ctx->drop = true;
}

static void
process_pktin(struct ctx *ctx, struct pipeline_result *result)
{
    if (ctx->pktin_agent || ctx->pktin_controller) {
        uint8_t reason = ctx->pktin_controller ? OF_PACKET_IN_REASON_ACTION : OF_PACKET_IN_REASON_NO_MATCH;
        pktin(result, reason, ctx->pktin_metadata);
    }
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
