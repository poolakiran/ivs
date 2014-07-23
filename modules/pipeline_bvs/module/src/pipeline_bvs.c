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

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

static const of_mac_addr_t slow_protocols_mac = { { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 } };
static const of_mac_addr_t packet_of_death_mac = { { 0x5C, 0x16, 0xC7, 0xFF, 0xFF, 0x04 } };
static const of_mac_addr_t cdp_mac = { { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc } };
static const of_mac_addr_t broadcast_mac = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

static void process_l2(struct ctx *ctx);
static void process_l3(struct ctx *ctx);
static void process_debug(struct ctx *ctx);
static void process_egress(struct ctx *ctx, uint32_t out_port, bool l3);
static bool check_vlan_membership(struct vlan_entry *vlan_entry, uint32_t in_port, bool *tagged);
static void flood_vlan(struct ctx *ctx);
static void span(struct ctx *ctx, struct span_group *span);
static struct debug_key make_debug_key(struct ctx *ctx);
static struct vlan_acl_key make_vlan_acl_key(struct ctx *ctx);
static struct ingress_acl_key make_ingress_acl_key(struct ctx *ctx);
static uint32_t group_to_table_id(uint32_t group_id);
static void mark_pktin_agent(struct ctx *ctx, uint64_t flag);
static void mark_pktin_controller(struct ctx *ctx, uint64_t flag);
static void mark_drop(struct ctx *ctx);
static void process_pktin(struct ctx *ctx);

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
    pipeline_bvs_register_next_hop_datatype();
    pipeline_bvs_table_port_register();
    pipeline_bvs_table_vlan_xlate_register();
    pipeline_bvs_table_egr_vlan_xlate_register();
    pipeline_bvs_table_vlan_register();
    pipeline_bvs_table_l2_register();
    pipeline_bvs_table_my_station_register();
    pipeline_bvs_table_l3_host_route_register();
    pipeline_bvs_table_l3_cidr_route_register();
    pipeline_bvs_table_flood_register();
    pipeline_bvs_table_ingress_acl_register();
    pipeline_bvs_table_debug_register();
    pipeline_bvs_table_ingress_mirror_register();
    pipeline_bvs_table_egress_mirror_register();
    pipeline_bvs_table_egress_acl_register();
    pipeline_bvs_table_vlan_acl_register();
    pipeline_bvs_table_qos_weight_register();
    pipeline_bvs_group_ecmp_register();
    pipeline_bvs_group_lag_register();
    pipeline_bvs_group_span_register();
}

static void
pipeline_bvs_finish(void)
{
    indigo_cxn_async_channel_selector_unregister(pipeline_bvs_cxn_async_channel_selector);
    pipeline_bvs_unregister_next_hop_datatype();
    pipeline_bvs_table_port_unregister();
    pipeline_bvs_table_vlan_xlate_unregister();
    pipeline_bvs_table_egr_vlan_xlate_unregister();
    pipeline_bvs_table_vlan_unregister();
    pipeline_bvs_table_l2_unregister();
    pipeline_bvs_table_my_station_unregister();
    pipeline_bvs_table_l3_host_route_unregister();
    pipeline_bvs_table_l3_cidr_route_unregister();
    pipeline_bvs_table_flood_unregister();
    pipeline_bvs_table_ingress_acl_unregister();
    pipeline_bvs_table_debug_unregister();
    pipeline_bvs_table_ingress_mirror_unregister();
    pipeline_bvs_table_egress_mirror_unregister();
    pipeline_bvs_table_egress_acl_unregister();
    pipeline_bvs_table_vlan_acl_unregister();
    pipeline_bvs_table_qos_weight_unregister();
    pipeline_bvs_group_ecmp_unregister();
    pipeline_bvs_group_span_unregister();
    pipeline_bvs_group_lag_unregister();
}

static indigo_error_t
pipeline_bvs_process(struct ind_ovs_parsed_key *key,
                     struct xbuf *stats,
                     struct action_context *actx)
{
    struct ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.key = key;
    ctx.stats = stats;
    ctx.actx = actx;

    /* TODO revise when TCP flags are added to the parsed key */
    ctx.hash = murmur_hash(key, sizeof(*key), 0);

    process_l2(&ctx);

    return INDIGO_ERROR_NONE;
}

static void
process_l2(struct ctx *ctx)
{
    ctx->original_vlan_vid = VLAN_VID(ntohs(ctx->key->vlan));

    /* Ingress mirror */
    struct ingress_mirror_entry *ingress_mirror_entry =
        pipeline_bvs_table_ingress_mirror_lookup(ctx->key->in_port);
    if (ingress_mirror_entry) {
        span(ctx, ingress_mirror_entry->value.span);
    }

    struct ind_ovs_port_counters *port_counters = ind_ovs_port_stats_select(ctx->key->in_port);
    AIM_ASSERT(port_counters != NULL);

    if (ctx->key->ethernet.eth_dst[0] & 1) {
        if (!memcmp(ctx->key->ethernet.eth_dst, broadcast_mac.addr, OF_MAC_ADDR_BYTES)) {
            /* Increment broadcast port counters */
            pipeline_add_stats(ctx->stats, &port_counters->rx_broadcast_stats_handle);
        } else {
            /* Increment multicast port counters */
            pipeline_add_stats(ctx->stats, &port_counters->rx_multicast_stats_handle);
        }
    } else {
        /* Increment unicast port counters */
        pipeline_add_stats(ctx->stats, &port_counters->rx_unicast_stats_handle);
    }

    bool packet_of_death = false;
    if (ctx->key->ethertype == htons(0x88cc)) {
        if (!memcmp(ctx->key->ethernet.eth_src, packet_of_death_mac.addr, OF_MAC_ADDR_BYTES)) {
            packet_of_death = true;
        } else if (!memcmp(ctx->key->ethernet.eth_dst, cdp_mac.addr, OF_MAC_ADDR_BYTES)) {
            AIM_LOG_VERBOSE("dropping CDP packet");
            mark_drop(ctx);
        } else {
            AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(ctx->key->ethertype));
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
            mark_drop(ctx);
        }
    }

    if (!memcmp(ctx->key->ethernet.eth_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("sending slow protocols packet directly to controller");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
        mark_drop(ctx);
    }

    /* HACK early drop for PDUs */
    if (ctx->drop) {
        process_pktin(ctx);
        return;
    }

    struct port_entry *port_entry = pipeline_bvs_table_port_lookup(ctx->key->in_port);
    if (!port_entry) {
        return;
    }

    ctx->ingress_lag_id = port_entry->value.lag_id;

    if (packet_of_death) {
        if (port_entry->value.packet_of_death) {
            AIM_LOG_VERBOSE("sending packet of death to cpu");
            action_controller(ctx->actx, IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, 0));
        } else {
            AIM_LOG_VERBOSE("ignoring packet of death on not-allowed port");
        }
        return;
    }

    uint16_t vlan_vid = VLAN_VID(ntohs(ctx->key->vlan));

    struct vlan_acl_key vlan_acl_key = make_vlan_acl_key(ctx);
    struct vlan_acl_entry *vlan_acl_entry =
        pipeline_bvs_table_vlan_acl_lookup(&vlan_acl_key);
    if (vlan_acl_entry) {
        ctx->vrf = vlan_acl_entry->value.vrf;
        ctx->l3_interface_class_id = vlan_acl_entry->value.l3_interface_class_id;
        ctx->l3_src_class_id = vlan_acl_entry->value.l3_src_class_id;
    } else {
        if (ctx->key->vlan & htons(VLAN_CFI_BIT)) {
            struct vlan_xlate_entry *vlan_xlate_entry =
                pipeline_bvs_table_vlan_xlate_lookup(VLAN_XLATE_TYPE_PORT_GROUP_ID, port_entry->value.vlan_xlate_port_group_id, vlan_vid);
            if (vlan_xlate_entry == NULL) {
                /* For backwards compatibility */
                vlan_xlate_entry = pipeline_bvs_table_vlan_xlate_lookup(VLAN_XLATE_TYPE_LAG_ID, ctx->ingress_lag_id, vlan_vid);
            }
            if (vlan_xlate_entry) {
                vlan_vid = vlan_xlate_entry->value.new_vlan_vid;
                action_set_vlan_vid(ctx->actx, vlan_vid);
            } else if (port_entry->value.require_vlan_xlate) {
                AIM_LOG_VERBOSE("vlan_xlate required and missed, dropping");
                mark_drop(ctx);
                process_debug(ctx);
                process_pktin(ctx);
                return;
            }
        } else {
            vlan_vid = port_entry->value.default_vlan_vid;
            action_push_vlan(ctx->actx);
            action_set_vlan_vid(ctx->actx, vlan_vid);
        }
    }

    ctx->internal_vlan_vid = vlan_vid;

    struct vlan_entry *vlan_entry = pipeline_bvs_table_vlan_lookup(vlan_vid);
    if (!vlan_entry) {
        AIM_LOG_VERBOSE("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        mark_drop(ctx);
        return;
    }

    if (!check_vlan_membership(vlan_entry, ctx->key->in_port, NULL)) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", ctx->key->in_port, vlan_vid);
        mark_drop(ctx);
        return;
    }

    if (!port_entry->value.disable_vlan_counters) {
        pipeline_add_stats(ctx->stats, ind_ovs_rx_vlan_stats_select(vlan_vid));
    }

    if (!vlan_acl_entry) {
        AIM_LOG_VERBOSE("VLAN %u: vrf=%u", vlan_vid, vlan_entry->value.vrf);
        ctx->vrf = vlan_entry->value.vrf;
        ctx->l3_interface_class_id = vlan_entry->value.l3_interface_class_id;
    }

    /* Source lookup */
    struct l2_entry *src_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, ctx->key->ethernet.eth_src);
    if (src_l2_entry) {
        pipeline_add_stats(ctx->stats, &src_l2_entry->stats_handle);

        if (src_l2_entry->value.lag == NULL) {
            AIM_LOG_VERBOSE("L2 source discard");
            mark_drop(ctx);
        } else if (!port_entry->value.disable_src_mac_check) {
            if (src_l2_entry->value.lag->id != ctx->ingress_lag_id) {
                AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE);
                mark_drop(ctx);
            }
        }
    } else {
        if (!port_entry->value.disable_src_mac_check) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_NEW_HOST);
            mark_drop(ctx);
        }
    }

    /* ARP offload */
    if (port_entry->value.arp_offload) {
        if (ctx->key->ethertype == htons(0x0806)) {
            AIM_LOG_VERBOSE("sending ARP packet to agent");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP);
            /* Continue forwarding packet */
        }
    }

    /* DHCP offload */
    if (port_entry->value.dhcp_offload) {
        if (ctx->key->ethertype == htons(0x0800) && ctx->key->ipv4.ipv4_proto == 17 &&
                (ctx->key->tcp.tcp_dst == htons(67) || ctx->key->tcp.tcp_dst == htons(68))) {
            AIM_LOG_VERBOSE("sending DHCP packet to agent");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_DHCP);
            mark_drop(ctx);
        }
    }

    /* Check for broadcast/multicast */
    if (ctx->key->ethernet.eth_dst[0] & 1) {
        process_debug(ctx);
        process_pktin(ctx);

        if (ctx->drop) {
            return;
        }

        flood_vlan(ctx);

        return;
    }

    if (ctx->pktin_metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST) {
        process_debug(ctx);
        process_pktin(ctx);
        return;
    }

    if (pipeline_bvs_table_my_station_lookup(ctx->key->ethernet.eth_dst)) {
        process_l3(ctx);
        return;
    }

    /* Destination lookup */
    struct l2_entry *dst_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, ctx->key->ethernet.eth_dst);
    if (!dst_l2_entry) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");

        process_debug(ctx);
        process_pktin(ctx);

        if (ctx->drop) {
            return;
        }

        flood_vlan(ctx);

        return;
    }

    if (dst_l2_entry->value.lag == NULL) {
        AIM_LOG_VERBOSE("hit in destination l2table lookup, discard");
        mark_drop(ctx);
    } else {
        AIM_LOG_VERBOSE("hit in destination l2table lookup, lag %u", dst_l2_entry->value.lag->id);
    }

    process_debug(ctx);
    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_group_lag_select(dst_l2_entry->value.lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        return;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", lag_bucket->port_no);

    process_egress(ctx, lag_bucket->port_no, false);
}

static void
process_l3(struct ctx *ctx)
{
    struct next_hop *next_hop = NULL;
    bool l3_cpu = false;
    bool acl_cpu = false;
    bool drop = false;
    bool bad_ttl = ctx->key->ipv4.ipv4_ttl <= 1;

    if (bad_ttl) {
        AIM_LOG_VERBOSE("sending TTL expired packet to agent");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_TTL_EXPIRED);
        mark_drop(ctx);
        process_debug(ctx);
        process_pktin(ctx);
        return;
    } else {
        struct l3_host_route_entry *l3_host_route_entry =
            pipeline_bvs_table_l3_host_route_lookup(ctx->vrf, ctx->key->ipv4.ipv4_dst);
        if (l3_host_route_entry != NULL) {
            next_hop = &l3_host_route_entry->value.next_hop;
            l3_cpu = l3_host_route_entry->value.cpu;
        } else {
            struct l3_cidr_route_entry *l3_cidr_route_entry =
                pipeline_bvs_table_l3_cidr_route_lookup(ctx->vrf, ctx->key->ipv4.ipv4_dst);
            if (l3_cidr_route_entry != NULL) {
                next_hop = &l3_cidr_route_entry->value.next_hop;
                l3_cpu = l3_cidr_route_entry->value.cpu;
            }
        }
    }

    process_debug(ctx);

    struct ingress_acl_key ingress_acl_key = make_ingress_acl_key(ctx);
    struct ingress_acl_entry *ingress_acl_entry =
        pipeline_bvs_table_ingress_acl_lookup(&ingress_acl_key);
    if (ingress_acl_entry) {
        pipeline_add_stats(ctx->stats, &ingress_acl_entry->stats_handle);
        drop = drop || ingress_acl_entry->value.drop;
        acl_cpu = ingress_acl_entry->value.cpu;
        if (ingress_acl_entry->value.next_hop.type != NEXT_HOP_TYPE_NULL) {
            next_hop = &ingress_acl_entry->value.next_hop;
        }
    }

    bool hit = next_hop != NULL;
    bool valid_next_hop = next_hop != NULL && next_hop->type != NEXT_HOP_TYPE_NULL;

    if (l3_cpu) {
        AIM_LOG_VERBOSE("L3 copy to CPU");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_CPU);
    }

    if (acl_cpu) {
        AIM_LOG_VERBOSE("Ingress ACL copy to CPU");
        mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_INGRESS_ACL);
    }

    if (l3_cpu || acl_cpu) {
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

    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    AIM_ASSERT(valid_next_hop);

    if (next_hop->type == NEXT_HOP_TYPE_ECMP) {
        struct ecmp_bucket *ecmp_bucket = pipeline_bvs_group_ecmp_select(next_hop->ecmp, ctx->hash);
        if (ecmp_bucket == NULL) {
            AIM_LOG_VERBOSE("empty ecmp group %d", next_hop->ecmp->id);
            return;
        }

        next_hop = &ecmp_bucket->next_hop;
    }

    AIM_ASSERT(next_hop->type == NEXT_HOP_TYPE_LAG);

    AIM_LOG_VERBOSE("next-hop: eth_src=%{mac} eth_dst=%{mac} vlan=%u lag_id=%u",
                    next_hop->new_eth_src.addr, next_hop->new_eth_dst.addr,
                    next_hop->new_vlan_vid, next_hop->lag->id);

    struct lag_bucket *lag_bucket = pipeline_bvs_group_lag_select(next_hop->lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        return;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", lag_bucket->port_no);

    ctx->internal_vlan_vid = next_hop->new_vlan_vid;
    action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
    action_set_eth_src(ctx->actx, next_hop->new_eth_src);
    action_set_eth_dst(ctx->actx, next_hop->new_eth_dst);
    action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl - 1);

    process_egress(ctx, lag_bucket->port_no, true);
}

static void
process_debug(struct ctx *ctx)
{
    struct debug_key debug_key = make_debug_key(ctx);
    struct debug_entry *debug_entry =
        pipeline_bvs_table_debug_lookup(&debug_key);
    if (!debug_entry) {
        return;
    }

    pipeline_add_stats(ctx->stats, &debug_entry->stats_handle);

    if (debug_entry->value.span != NULL) {
        if (ctx->original_vlan_vid != 0) {
            action_set_vlan_vid(ctx->actx, ctx->original_vlan_vid);
        } else {
            action_pop_vlan(ctx->actx);
        }
        span(ctx, debug_entry->value.span);
        action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
    }

    if (debug_entry->value.cpu) {
        if (!(ctx->pktin_metadata & (OFP_BSN_PKTIN_FLAG_ARP|
                                     OFP_BSN_PKTIN_FLAG_DHCP|
                                     OFP_BSN_PKTIN_FLAG_STATION_MOVE))) {
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_DEBUG);
        }
    }

    if (debug_entry->value.drop) {
        mark_drop(ctx);
    }
}

static void
process_egress(struct ctx *ctx, uint32_t out_port, bool l3)
{
    struct vlan_entry *vlan_entry =
        pipeline_bvs_table_vlan_lookup(ctx->internal_vlan_vid);
    if (!vlan_entry) {
        AIM_LOG_VERBOSE("Packet routed to unconfigured vlan %u", ctx->internal_vlan_vid);
        return;
    }

    bool out_port_tagged;
    if (!check_vlan_membership(vlan_entry, out_port, &out_port_tagged)) {
        AIM_LOG_VERBOSE("output port %u not allowed on vlan %u", out_port, ctx->internal_vlan_vid);
        return;
    }

    struct port_entry *dst_port_entry = pipeline_bvs_table_port_lookup(out_port);
    if (!dst_port_entry) {
        return;
    }

    if (!l3 && dst_port_entry->value.lag_id != OF_GROUP_ANY &&
            dst_port_entry->value.lag_id == ctx->ingress_lag_id) {
        AIM_LOG_VERBOSE("skipping ingress LAG %u", ctx->ingress_lag_id);
        return;
    }

    if (!dst_port_entry->value.disable_vlan_counters) {
        pipeline_add_stats(ctx->stats, ind_ovs_tx_vlan_stats_select(ctx->internal_vlan_vid));
    }

    struct ind_ovs_port_counters *port_counters = ind_ovs_port_stats_select(out_port);
    AIM_ASSERT(port_counters != NULL);

    if (ctx->key->ethernet.eth_dst[0] & 1) {
        if (!memcmp(ctx->key->ethernet.eth_dst, broadcast_mac.addr, OF_MAC_ADDR_BYTES)) {
            /* Increment broadcast port counters */
            pipeline_add_stats(ctx->stats, &port_counters->tx_broadcast_stats_handle);
        } else {
            /* Increment multicast port counters */
            pipeline_add_stats(ctx->stats, &port_counters->tx_multicast_stats_handle);
        }
    } else {
        /* Increment unicast port counters */
        pipeline_add_stats(ctx->stats, &port_counters->tx_unicast_stats_handle);
    }

    /* Egress VLAN translation */
    uint16_t tag = ctx->internal_vlan_vid;
    if (!out_port_tagged) {
        action_pop_vlan(ctx->actx);
        tag = 0;
    } else {
        struct egr_vlan_xlate_entry *egr_vlan_xlate_entry =
            pipeline_bvs_table_egr_vlan_xlate_lookup(EGR_VLAN_XLATE_TYPE_PORT_GROUP_ID, dst_port_entry->value.vlan_xlate_port_group_id, ctx->internal_vlan_vid);
        if (egr_vlan_xlate_entry == NULL) {
            /* For backwards compatibility */
            egr_vlan_xlate_entry = pipeline_bvs_table_egr_vlan_xlate_lookup(EGR_VLAN_XLATE_TYPE_PORT, out_port, ctx->internal_vlan_vid);
        }
        if (egr_vlan_xlate_entry) {
            tag = egr_vlan_xlate_entry->value.new_vlan_vid;
            action_set_vlan_vid(ctx->actx, tag);
        }
    }

    /* Egress ACL */
    if (l3) {
        struct egress_acl_key key = {
            .vlan_vid = tag,
            .egr_port_group_id = dst_port_entry->value.egr_port_group_id,
            .l3_interface_class_id = ctx->l3_interface_class_id,
        };

        struct egress_acl_entry *entry =
            pipeline_bvs_table_egress_acl_lookup(&key);
        if (entry && entry->value.drop) {
            return;
        }
    }

    /* Egress mirror */
    struct egress_mirror_entry *egress_mirror_entry =
        pipeline_bvs_table_egress_mirror_lookup(out_port);
    if (egress_mirror_entry) {
        span(ctx, egress_mirror_entry->value.span);
    }

    action_output(ctx->actx, out_port);
}

static bool
check_vlan_membership(struct vlan_entry *vlan_entry, uint32_t in_port, bool *tagged)
{
    int i;
    for (i = 0; i < vlan_entry->value.num_ports; i++) {
        if (vlan_entry->value.ports[i] == in_port) {
            if (tagged) {
                *tagged = i < vlan_entry->value.num_tagged_ports;
            }
            return true;
        }
    }

    if (in_port == OVSP_LOCAL) {
        if (tagged) {
            *tagged = true;
        }
        return true;
    }

    return false;
}

static void
flood_vlan(struct ctx *ctx)
{
    struct flood_key key = { .lag_id = ctx->ingress_lag_id };
    struct flood_entry *entry = pipeline_bvs_table_flood_lookup(&key);
    if (entry == NULL) {
        return;
    }

    int i;
    for (i = 0; i < entry->value.num_lags; i++) {
        struct lag_group *lag = entry->value.lags[i];

        struct lag_bucket *lag_bucket = pipeline_bvs_group_lag_select(lag, ctx->hash);
        if (lag_bucket == NULL) {
            AIM_LOG_VERBOSE("empty LAG %d", lag->id);
            continue;
        }
        AIM_LOG_VERBOSE("selected LAG %u port %u", lag->id, lag_bucket->port_no);

        process_egress(ctx, lag_bucket->port_no, false);
    }
}

static void
span(struct ctx *ctx, struct span_group *span)
{
    struct lag_bucket *lag_bucket = pipeline_bvs_group_lag_select(span->value.lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        return;
    }

    AIM_LOG_VERBOSE("Selected LAG port %u", lag_bucket->port_no);

    action_output(ctx->actx, lag_bucket->port_no);
}

static struct debug_key
make_debug_key(struct ctx *ctx)
{
    struct debug_key key = {
        .in_port = ctx->key->in_port,
        .eth_type = ntohs(ctx->key->ethertype),
        .vlan_vid = ctx->internal_vlan_vid,
        .ipv4_src = ntohl(ctx->key->ipv4.ipv4_src),
        .ipv4_dst = ntohl(ctx->key->ipv4.ipv4_dst),
        .ip_proto = ctx->key->ipv4.ipv4_proto,
        .ip_tos = ctx->key->ipv4.ipv4_tos,
        .tcp_flags = 0,
    };

    memcpy(&key.eth_src, ctx->key->ethernet.eth_src, OF_MAC_ADDR_BYTES);
    memcpy(&key.eth_dst, ctx->key->ethernet.eth_dst, OF_MAC_ADDR_BYTES);

    if (key.ip_proto == IPPROTO_TCP) {
        key.tp_src = ntohs(ctx->key->tcp.tcp_src);
        key.tp_dst = ntohs(ctx->key->tcp.tcp_dst);
        key.tcp_flags = ntohs(ctx->key->tcp_flags);
    } else if (key.ip_proto == IPPROTO_UDP) {
        key.tp_src = ntohs(ctx->key->udp.udp_src);
        key.tp_dst = ntohs(ctx->key->udp.udp_dst);
    } else {
        key.tp_src = 0;
        key.tp_dst = 0;
    }

    return key;
}

static struct vlan_acl_key
make_vlan_acl_key(struct ctx *ctx)
{
    struct vlan_acl_key key = {
        .vlan_vid = VLAN_VID(ntohs(ctx->key->vlan)),
        .pad = 0,
    };
    memcpy(&key.eth_src, ctx->key->ethernet.eth_src, OF_MAC_ADDR_BYTES);
    memcpy(&key.eth_dst, ctx->key->ethernet.eth_dst, OF_MAC_ADDR_BYTES);

    return key;
}

static struct ingress_acl_key
make_ingress_acl_key(struct ctx *ctx)
{
    struct ingress_acl_key key = {
        .in_port = ctx->key->in_port,
        .vlan_vid = ctx->internal_vlan_vid,
        .ip_proto = ctx->key->ipv4.ipv4_proto,
        .pad = 0,
        .vrf = ctx->vrf,
        .l3_interface_class_id = ctx->l3_interface_class_id,
        .l3_src_class_id = ctx->l3_src_class_id,
        .ipv4_src = ntohl(ctx->key->ipv4.ipv4_src),
        .ipv4_dst = ntohl(ctx->key->ipv4.ipv4_dst),
        .tcp_flags = 0,
        .pad2 = 0,
    };

    if (key.ip_proto == IPPROTO_TCP) {
        key.tp_src = ntohs(ctx->key->tcp.tcp_src);
        key.tp_dst = ntohs(ctx->key->tcp.tcp_dst);
        key.tcp_flags = ntohs(ctx->key->tcp_flags);
    } else if (key.ip_proto == IPPROTO_UDP) {
        key.tp_src = ntohs(ctx->key->udp.udp_src);
        key.tp_dst = ntohs(ctx->key->udp.udp_dst);
    } else {
        key.tp_src = 0;
        key.tp_dst = 0;
    }

    return key;
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
process_pktin(struct ctx *ctx)
{
    if (ctx->pktin_agent || ctx->pktin_controller) {
        uint8_t reason = ctx->pktin_controller ? OF_PACKET_IN_REASON_ACTION : OF_PACKET_IN_REASON_NO_MATCH;
        action_controller(ctx->actx, IVS_PKTIN_USERDATA(reason, ctx->pktin_metadata));
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
