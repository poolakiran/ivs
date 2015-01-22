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
static const of_mac_addr_t zero_mac = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

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

enum pipeline_bvs_version version;

static uint32_t port_sampling_rate[SLSHARED_CONFIG_OF_PORT_MAX+1];

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

/*
 * Bundle sort order:
 *  - group-adds in ascending table-id order (lag, ecmp, span)
 *  - all other messages
 *  - group-deletes in descending table-id order (span, ecmp, lag)
 */
static int
sort_key(of_object_t *obj)
{
    if (obj->object_id == OF_GROUP_ADD) {
        uint32_t group_id;
        of_group_add_group_id_get(obj, &group_id);
        return -1000 + (group_id >> 24);
    } else if (obj->object_id == OF_GROUP_DELETE) {
        uint32_t group_id;
        of_group_delete_group_id_get(obj, &group_id);
        return 1000 - (group_id >> 24);
    } else {
        return 0;
    }
}

static int
bundle_comparator(of_object_t *a, of_object_t *b)
{
    return sort_key(a) - sort_key(b);
}

/*
 * Set the port ingress sampling rate.
 * Sampling rate is set as a probability which is a fraction of UINT32_MAX.
 *
 * Revalidate kflows after setting the sampling rate
 */
static indigo_error_t
port_sampling_rate_set(of_port_no_t port_no, uint32_t sampling_rate,
                       indigo_cxn_id_t cxn_id)
{
    AIM_ASSERT(port_no <= SLSHARED_CONFIG_OF_PORT_MAX,
               "Port (%u) out of range", port_no);

    sampling_rate = sampling_rate? UINT32_MAX/sampling_rate : 0;
    AIM_LOG_VERBOSE("port %u sampling rate set to %u", port_no, sampling_rate);
    port_sampling_rate[port_no] = sampling_rate;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
pipeline_bvs_init(const char *name)
{
    if (!strcmp(name, "bvs-2.0")) {
        version = V2_0;
    } else {
        version = V1_0;
    }

    indigo_cxn_async_channel_selector_register(pipeline_bvs_cxn_async_channel_selector);
    indigo_cxn_bundle_comparator_set(bundle_comparator);
    sflowa_sampling_rate_handler_register(port_sampling_rate_set);
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
    pipeline_bvs_table_source_miss_override_register();
    pipeline_bvs_table_floating_ip_forward_register();
    pipeline_bvs_table_floating_ip_reverse_register();
    pipeline_bvs_table_qos_weight_register();
    pipeline_bvs_table_breakout_register();
    pipeline_bvs_table_arp_offload_register();
    pipeline_bvs_group_ecmp_register();
    pipeline_bvs_group_lag_register();
    pipeline_bvs_group_span_register();
    pipeline_bvs_table_lag_register();
    pipeline_bvs_table_span_register();
    pipeline_bvs_table_ecmp_register();
}

static void
pipeline_bvs_finish(void)
{
    indigo_cxn_async_channel_selector_unregister(pipeline_bvs_cxn_async_channel_selector);
    indigo_cxn_bundle_comparator_set(NULL);
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
    pipeline_bvs_table_source_miss_override_unregister();
    pipeline_bvs_table_floating_ip_forward_unregister();
    pipeline_bvs_table_floating_ip_reverse_unregister();
    pipeline_bvs_table_qos_weight_unregister();
    pipeline_bvs_table_breakout_unregister();
    pipeline_bvs_table_arp_offload_unregister();
    pipeline_bvs_group_ecmp_unregister();
    pipeline_bvs_group_span_unregister();
    pipeline_bvs_group_lag_unregister();
    pipeline_bvs_table_lag_unregister();
    pipeline_bvs_table_span_unregister();
    pipeline_bvs_table_ecmp_unregister();
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
    ctx->recursion_depth++;
    if (ctx->recursion_depth > 10) {
        AIM_LOG_INTERNAL("Exceeded max recursion depth");
        return;
    }

    ctx->original_vlan_vid = VLAN_VID(ntohs(ctx->key->vlan));

    /* Ingress mirror */
    struct ingress_mirror_entry *ingress_mirror_entry =
        pipeline_bvs_table_ingress_mirror_lookup(ctx->key->in_port);
    if (ingress_mirror_entry) {
        span(ctx, ingress_mirror_entry->value.span);
    }

    if (ctx->key->in_port <= SLSHARED_CONFIG_OF_PORT_MAX &&
        port_sampling_rate[ctx->key->in_port]) {
        action_sample_to_controller(ctx->actx, IVS_PKTIN_USERDATA(0, OFP_BSN_PKTIN_FLAG_SFLOW),
                                    port_sampling_rate[ctx->key->in_port]);
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
            if (version == V1_0) {
                AIM_LOG_VERBOSE("dropping CDP packet");
            } else {
                AIM_LOG_VERBOSE("sending CDP packet directly to controller");
                mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
            }
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
    ctx->ingress_lag = port_entry->value.ingress_lag;

    if (packet_of_death) {
        if (port_entry->value.packet_of_death) {
            AIM_LOG_VERBOSE("sending packet of death to cpu");
            action_controller(ctx->actx, IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, 0));
        } else {
            AIM_LOG_VERBOSE("ignoring packet of death on not-allowed port");
        }
        return;
    }

    uint16_t tag = VLAN_VID(ntohs(ctx->key->vlan));
    uint16_t vlan_vid;

    if (!(ctx->key->vlan & htons(VLAN_CFI_BIT))) {
        AIM_LOG_VERBOSE("Using VLAN from port table");
        vlan_vid = port_entry->value.default_vlan_vid;
        action_push_vlan(ctx->actx);
        action_set_vlan_vid(ctx->actx, vlan_vid);
    } else {
        struct vlan_xlate_entry *vlan_xlate_entry =
            pipeline_bvs_table_vlan_xlate_lookup(port_entry->value.vlan_xlate_port_group_id, tag);
        if (vlan_xlate_entry) {
            AIM_LOG_VERBOSE("Using VLAN from vlan_xlate");
            vlan_vid = vlan_xlate_entry->value.new_vlan_vid;
            action_set_vlan_vid(ctx->actx, vlan_vid);
        } else if (port_entry->value.require_vlan_xlate) {
            AIM_LOG_VERBOSE("vlan_xlate required and missed, dropping");
            mark_drop(ctx);
            process_debug(ctx);
            process_pktin(ctx);
            return;
        } else {
            AIM_LOG_VERBOSE("Using VLAN from packet");
            vlan_vid = tag;
        }
    }

    ctx->internal_vlan_vid = vlan_vid;
    ctx->cur_tag = vlan_vid;

    struct vlan_acl_key vlan_acl_key = make_vlan_acl_key(ctx);
    struct vlan_acl_entry *vlan_acl_entry =
        pipeline_bvs_table_vlan_acl_lookup(&vlan_acl_key);
    if (vlan_acl_entry) {
        ctx->vrf = vlan_acl_entry->value.vrf;
        ctx->l3_interface_class_id = vlan_acl_entry->value.l3_interface_class_id;
        ctx->l3_src_class_id = vlan_acl_entry->value.l3_src_class_id;
    }

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

    if (!memcmp(ctx->key->ethernet.eth_src, &zero_mac, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("L2 source zero, discarding");
        mark_drop(ctx);
        return;
    }

    /* Source lookup */
    struct l2_entry *src_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, ctx->key->ethernet.eth_src);

    bool disable_src_mac_check =
        port_entry->value.disable_src_mac_check &&
            !pipeline_bvs_table_source_miss_override_lookup(vlan_vid, ctx->key->in_port);

    if (src_l2_entry) {
        pipeline_add_stats(ctx->stats, &src_l2_entry->stats_handle);

        if (src_l2_entry->value.lag == NULL) {
            AIM_LOG_VERBOSE("L2 source discard");
            mark_drop(ctx);
        } else if (!disable_src_mac_check) {
            if (src_l2_entry->value.lag != ctx->ingress_lag) {
                AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE);
                mark_drop(ctx);
            }
        }
    } else {
        if (!disable_src_mac_check) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_NEW_HOST);
            mark_drop(ctx);
        }
    }

    /* ARP offload */
    if (ctx->key->ethertype == htons(0x0806)) {
        if (pipeline_bvs_table_arp_offload_lookup(
                ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip))) {
            AIM_LOG_VERBOSE("trapping ARP packet to VLAN %u IP %{ipv4a}", ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip));
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP);
            mark_drop(ctx);
            process_pktin(ctx);
            return;
        } else if (port_entry->value.arp_offload) {
            AIM_LOG_VERBOSE("sending ARP packet to agent");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP);
            /* Continue forwarding packet */
        }
    }

    /* DHCP offload */
    if (port_entry->value.dhcp_offload) {
        if (ctx->key->ethertype == htons(0x0800) && ctx->key->ipv4.ipv4_proto == 17 &&
                (ctx->key->tcp.tcp_dst == htons(67) || ctx->key->tcp.tcp_dst == htons(68)) &&
                !memcmp(ctx->key->ethernet.eth_dst, &broadcast_mac, OF_MAC_ADDR_BYTES)) {
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

    if (ctx->key->ethertype == htons(ETH_P_IP) &&
            pipeline_bvs_table_my_station_lookup(ctx->key->ethernet.eth_dst)) {
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
        AIM_LOG_VERBOSE("hit in destination l2table lookup, lag %s", lag_name(dst_l2_entry->value.lag));
    }

    process_debug(ctx);
    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    struct floating_ip_forward_entry *floating_ip_forward_entry =
        pipeline_bvs_table_floating_ip_forward_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_src), ctx->key->ethernet.eth_dst);
    if (floating_ip_forward_entry) {
        struct floating_ip_forward_value *v = &floating_ip_forward_entry->value;
        ctx->internal_vlan_vid = v->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, v->new_vlan_vid);
        action_set_eth_src(ctx->actx, v->new_eth_src);
        action_set_eth_dst(ctx->actx, v->new_eth_dst);
        action_set_ipv4_src(ctx->actx, v->new_ipv4_src);

        ctx->key->vlan = htons(VLAN_TCI_WITH_CFI(v->new_vlan_vid | VLAN_CFI_BIT, VLAN_PCP(ntohs(ctx->key->vlan))));
        memcpy(ctx->key->ethernet.eth_src, &v->new_eth_src, OF_MAC_ADDR_BYTES);
        memcpy(ctx->key->ethernet.eth_dst, &v->new_eth_dst, OF_MAC_ADDR_BYTES);
        ctx->key->ipv4.ipv4_src = htonl(v->new_ipv4_src);
        ctx->key->in_port = OVSP_LOCAL;
        process_l2(ctx);
        return;
    }

    struct floating_ip_reverse_entry *floating_ip_reverse_entry =
        pipeline_bvs_table_floating_ip_reverse_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_dst), ctx->key->ethernet.eth_dst);
    if (floating_ip_reverse_entry) {
        struct floating_ip_reverse_value *v = &floating_ip_reverse_entry->value;
        ctx->internal_vlan_vid = v->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, v->new_vlan_vid);
        action_set_eth_src(ctx->actx, v->new_eth_src);
        action_set_eth_dst(ctx->actx, v->new_eth_dst);
        action_set_ipv4_dst(ctx->actx, v->new_ipv4_dst);

        ctx->key->vlan = htons(VLAN_TCI_WITH_CFI(v->new_vlan_vid | VLAN_CFI_BIT, VLAN_PCP(ntohs(ctx->key->vlan))));
        memcpy(ctx->key->ethernet.eth_src, &v->new_eth_src, OF_MAC_ADDR_BYTES);
        memcpy(ctx->key->ethernet.eth_dst, &v->new_eth_dst, OF_MAC_ADDR_BYTES);
        ctx->key->ipv4.ipv4_dst = htonl(v->new_ipv4_dst);
        ctx->key->in_port = OVSP_LOCAL;
        process_l2(ctx);
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(dst_l2_entry->value.lag, ctx->hash);
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

    if (next_hop->type == NEXT_HOP_TYPE_LAG) {
        AIM_LOG_VERBOSE("next-hop: eth_src=%{mac} eth_dst=%{mac} vlan=%u lag=%s",
                        next_hop->new_eth_src.addr, next_hop->new_eth_dst.addr,
                        next_hop->new_vlan_vid, lag_name(next_hop->lag));
    } else if (next_hop->type == NEXT_HOP_TYPE_LAG_NOREWRITE) {
        AIM_LOG_VERBOSE("next-hop: lag=%s", lag_name(next_hop->lag));
    } else {
        AIM_DIE("Unexpected next hop type");
    }

    const uint8_t *eth_dst = ctx->key->ethernet.eth_dst;

    if (next_hop->type == NEXT_HOP_TYPE_LAG) {
        ctx->internal_vlan_vid = next_hop->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
        action_set_eth_src(ctx->actx, next_hop->new_eth_src);
        action_set_eth_dst(ctx->actx, next_hop->new_eth_dst);
        action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl - 1);
        ctx->key->ipv4.ipv4_ttl--;

        eth_dst = next_hop->new_eth_dst.addr;
    }

    struct floating_ip_forward_entry *floating_ip_forward_entry =
        pipeline_bvs_table_floating_ip_forward_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_src), eth_dst);
    if (floating_ip_forward_entry) {
        struct floating_ip_forward_value *v = &floating_ip_forward_entry->value;
        ctx->internal_vlan_vid = v->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, v->new_vlan_vid);
        action_set_eth_src(ctx->actx, v->new_eth_src);
        action_set_eth_dst(ctx->actx, v->new_eth_dst);
        action_set_ipv4_src(ctx->actx, v->new_ipv4_src);

        ctx->key->vlan = htons(VLAN_TCI_WITH_CFI(v->new_vlan_vid | VLAN_CFI_BIT, VLAN_PCP(ntohs(ctx->key->vlan))));
        memcpy(ctx->key->ethernet.eth_src, &v->new_eth_src, OF_MAC_ADDR_BYTES);
        memcpy(ctx->key->ethernet.eth_dst, &v->new_eth_dst, OF_MAC_ADDR_BYTES);
        ctx->key->ipv4.ipv4_src = htonl(v->new_ipv4_src);
        ctx->key->in_port = OVSP_LOCAL;
        process_l2(ctx);
        return;
    }

    struct floating_ip_reverse_entry *floating_ip_reverse_entry =
        pipeline_bvs_table_floating_ip_reverse_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_dst), eth_dst);
    if (floating_ip_reverse_entry) {
        struct floating_ip_reverse_value *v = &floating_ip_reverse_entry->value;
        ctx->internal_vlan_vid = v->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, v->new_vlan_vid);
        action_set_eth_src(ctx->actx, v->new_eth_src);
        action_set_eth_dst(ctx->actx, v->new_eth_dst);
        action_set_ipv4_dst(ctx->actx, v->new_ipv4_dst);

        ctx->key->vlan = htons(VLAN_TCI_WITH_CFI(v->new_vlan_vid | VLAN_CFI_BIT, VLAN_PCP(ntohs(ctx->key->vlan))));
        memcpy(ctx->key->ethernet.eth_src, &v->new_eth_src, OF_MAC_ADDR_BYTES);
        memcpy(ctx->key->ethernet.eth_dst, &v->new_eth_dst, OF_MAC_ADDR_BYTES);
        ctx->key->ipv4.ipv4_dst = htonl(v->new_ipv4_dst);
        ctx->key->in_port = OVSP_LOCAL;
        process_l2(ctx);
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(next_hop->lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        return;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", lag_bucket->port_no);

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
            dst_port_entry->value.ingress_lag == ctx->ingress_lag) {
        AIM_LOG_VERBOSE("skipping ingress LAG %s", lag_name(ctx->ingress_lag));
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
        tag = 0;
    } else {
        struct egr_vlan_xlate_entry *egr_vlan_xlate_entry =
            pipeline_bvs_table_egr_vlan_xlate_lookup(dst_port_entry->value.vlan_xlate_port_group_id, ctx->internal_vlan_vid);
        if (egr_vlan_xlate_entry) {
            tag = egr_vlan_xlate_entry->value.new_vlan_vid;
        }
    }

    /*
     * The current tag on the packet persists between calls to process_egress.
     * If one port we're flooding to is untagged and the next is tagged,
     * we have to pop the tag, output to the first port, push a tag, and
     * output to the second port.
     */
    if (tag != ctx->cur_tag) {
        if (tag == 0) {
            /* tagged -> untagged */
            action_pop_vlan(ctx->actx);
        } else if (ctx->cur_tag == 0) {
            /* untagged -> tagged */
            action_push_vlan(ctx->actx);
            action_set_vlan_vid(ctx->actx, tag);
        } else {
            /* different tag */
            action_set_vlan_vid(ctx->actx, tag);
        }
    }

    ctx->cur_tag = tag;

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

        struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(lag, ctx->hash);
        if (lag_bucket == NULL) {
            AIM_LOG_VERBOSE("empty LAG %s", lag_name(lag));
            continue;
        }
        AIM_LOG_VERBOSE("selected LAG %s port %u", lag_name(lag), lag_bucket->port_no);

        process_egress(ctx, lag_bucket->port_no, false);
    }
}

static void
span(struct ctx *ctx, struct span_group *span)
{
    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(span->value.lag, ctx->hash);
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
    pipeline_register("bvs-2.0", &pipeline_bvs_ops);
    pipeline_register("experimental", &pipeline_bvs_ops); /* For command-line compatibility */
}
