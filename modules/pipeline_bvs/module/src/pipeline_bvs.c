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
static void mark_pktin_agent(struct ctx *ctx, uint64_t flag, struct ind_ovs_pktin_socket pktin_soc);
static void mark_pktin_controller(struct ctx *ctx, uint64_t flag, struct ind_ovs_pktin_socket pktin_soc);
static void mark_drop(struct ctx *ctx);
static void process_pktin(struct ctx *ctx);
static bool process_floating_ip(struct ctx *ctx);

enum pipeline_bvs_version version;

static uint32_t port_sampling_rate[SLSHARED_CONFIG_OF_PORT_MAX+1];

struct pipeline_bvs_port_pktin_socket {
    struct ind_ovs_pktin_socket pktin_soc;
    bool in_use;
};

static struct pipeline_bvs_port_pktin_socket port_pktin_soc[SLSHARED_CONFIG_OF_PORT_MAX+1];

static struct ind_ovs_pktin_socket sflow_pktin_soc;
static struct ind_ovs_pktin_socket debug_acl_pktin_soc;

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
gentable_sort_key(uint16_t table_id)
{
    if (table_id == pipeline_bvs_table_lag_id) {
        return -1000;
    } else if (table_id == pipeline_bvs_table_ecmp_id) {
        return -999;
    } else if (table_id == pipeline_bvs_table_span_id) {
        return -998;
    } else {
        return 0;
    }
}

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
    } else if (obj->object_id == OF_BSN_GENTABLE_ENTRY_ADD) {
        uint16_t table_id;
        of_bsn_gentable_entry_add_table_id_get(obj, &table_id);
        return gentable_sort_key(table_id);
    } else if (obj->object_id == OF_BSN_GENTABLE_ENTRY_DELETE) {
        uint16_t table_id;
        of_bsn_gentable_entry_delete_table_id_get(obj, &table_id);
        return -gentable_sort_key(table_id);
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

static indigo_core_listener_result_t
pipeline_bvs_port_status_handler(of_port_status_t *port_status)
{
    uint8_t reason;

    of_port_status_reason_get(port_status, &reason);
    of_port_desc_t port_desc;
    of_port_status_desc_bind(port_status, &port_desc);

    of_port_no_t port_no;
    of_port_desc_port_no_get(&port_desc, &port_no);

    if (reason == OF_PORT_CHANGE_REASON_ADD) {
        AIM_ASSERT(port_pktin_soc[port_no].in_use == false,
                   "Port %u already in use", port_no);

        /* Create pktin socket for this port */
        if (port_no <= SLSHARED_CONFIG_OF_PORT_MAX) {
            ind_ovs_pktin_socket_register(&port_pktin_soc[port_no].pktin_soc,
                                          pipeline_bvs_process_port_pktin,
                                          PORT_PKTIN_INTERVAL, PKTIN_BURST);
            port_pktin_soc[port_no].in_use = true;
        }

        /* Use tc to set up queues for this port */
        of_port_name_t if_name;
        of_port_desc_name_get(&port_desc, &if_name);
        pipeline_bvs_setup_tc(if_name);
    } else if (reason == OF_PORT_CHANGE_REASON_DELETE &&
        port_pktin_soc[port_no].in_use == true) {
        ind_ovs_pktin_socket_unregister(&port_pktin_soc[port_no].pktin_soc);
        port_pktin_soc[port_no].in_use = false;
    }

    return INDIGO_CORE_LISTENER_RESULT_PASS;
}

static void
pipeline_bvs_port_status_register(void)
{
    /* Register listener for port_status msg */
    if (indigo_core_port_status_listener_register(pipeline_bvs_port_status_handler) < 0) {
        AIM_LOG_ERROR("Failed to register for port_status");
    }
}

static void
pipeline_bvs_port_status_unregister(void)
{
    indigo_core_port_status_listener_unregister(pipeline_bvs_port_status_handler);
}

static void
pipeline_bvs_pktin_socket_register()
{
    /* Register the sflow pktin socket */
    ind_ovs_pktin_socket_register(&sflow_pktin_soc,
                                  pipeline_bvs_process_sflow_pktin,
                                  GLOBAL_PKTIN_INTERVAL, PKTIN_BURST);

    /* Register the debug/acl pktin socket */
    ind_ovs_pktin_socket_register(&debug_acl_pktin_soc, NULL,
                                  GLOBAL_PKTIN_INTERVAL, PKTIN_BURST);
}

static void
pipeline_bvs_pktin_socket_unregister()
{
    /* Unregister the sflow pktin socket */
    ind_ovs_pktin_socket_unregister(&sflow_pktin_soc);

    /* Unregister the debug/acl pktin socket */
    ind_ovs_pktin_socket_unregister(&debug_acl_pktin_soc);

    /* Unregister port pktin sockets */
    int i;
    for (i = 0; i <= SLSHARED_CONFIG_OF_PORT_MAX; i++) {
        if (port_pktin_soc[i].in_use == true) {
            ind_ovs_pktin_socket_unregister(&port_pktin_soc[i].pktin_soc);
            port_pktin_soc[i].in_use = false;
        }
    }
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
    pipeline_bvs_table_arp_cache_register();
    pipeline_bvs_group_ecmp_register();
    pipeline_bvs_group_lag_register();
    pipeline_bvs_group_span_register();
    pipeline_bvs_table_lag_register();
    pipeline_bvs_table_span_register();
    pipeline_bvs_table_ecmp_register();
    pipeline_inband_queue_priority_set(QUEUE_PRIORITY_INBAND);
    pipeline_bvs_stats_init();
    pipeline_bvs_port_status_register();
    pipeline_bvs_pktin_socket_register();
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
    pipeline_bvs_table_arp_cache_unregister();
    pipeline_bvs_group_ecmp_unregister();
    pipeline_bvs_group_span_unregister();
    pipeline_bvs_group_lag_unregister();
    pipeline_bvs_table_lag_unregister();
    pipeline_bvs_table_span_unregister();
    pipeline_bvs_table_ecmp_unregister();
    pipeline_inband_queue_priority_set(QUEUE_PRIORITY_INVALID);
    pipeline_bvs_stats_finish();
    pipeline_bvs_port_status_unregister();
    pipeline_bvs_pktin_socket_unregister();
}

static indigo_error_t
pipeline_bvs_process(struct ind_ovs_parsed_key *key,
                     struct ind_ovs_parsed_key *mask,
                     struct xbuf *stats,
                     struct action_context *actx)
{
    pipeline_add_stats(stats, &pipeline_bvs_stats[PIPELINE_BVS_STATS_INGRESS]);

    uint64_t populated = mask->populated;
    memset(mask, 0xff, sizeof(*mask));
    key->tcp_flags = 0;
    mask->tcp_flags = 0;
    mask->populated = populated;

    struct ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.key = key;
    ctx.stats = stats;
    ctx.actx = actx;

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
    ctx->skb_priority = ctx->key->priority;

    /* Ingress mirror */
    struct ingress_mirror_entry *ingress_mirror_entry =
        pipeline_bvs_table_ingress_mirror_lookup(ctx->key->in_port);
    if (ingress_mirror_entry) {
        span(ctx, ingress_mirror_entry->value.span);
    }

    if (ctx->key->in_port <= SLSHARED_CONFIG_OF_PORT_MAX &&
        port_sampling_rate[ctx->key->in_port]) {
        uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&sflow_pktin_soc);
        uint64_t userdata = IVS_PKTIN_USERDATA(0, OFP_BSN_PKTIN_FLAG_SFLOW);
        action_sample_to_userspace(ctx->actx, &userdata, sizeof(uint64_t), netlink_port,
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
                mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU, port_pktin_soc[ctx->key->in_port].pktin_soc);
            }
            PIPELINE_STAT(PDU);
            mark_drop(ctx);
        } else {
            AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(ctx->key->ethertype));
            PIPELINE_STAT(PDU);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU, port_pktin_soc[ctx->key->in_port].pktin_soc);
            mark_drop(ctx);
        }
    }

    if (!memcmp(ctx->key->ethernet.eth_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("sending slow protocols packet directly to controller");
        PIPELINE_STAT(PDU);
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU, port_pktin_soc[ctx->key->in_port].pktin_soc);
        mark_drop(ctx);
    }

    /* HACK early drop for PDUs */
    if (ctx->drop) {
        process_pktin(ctx);
        return;
    }

    struct port_entry *port_entry = pipeline_bvs_table_port_lookup(ctx->key->in_port);
    if (!port_entry) {
        PIPELINE_STAT(BAD_PORT);
        return;
    }

    ctx->ingress_lag_id = port_entry->value.lag_id;
    ctx->ingress_lag = port_entry->value.ingress_lag;
    ctx->ingress_port_group_id = port_entry->value.ingress_port_group_id;

    if (packet_of_death) {
        PIPELINE_STAT(PACKET_OF_DEATH);
        if (port_entry->value.packet_of_death) {
            AIM_LOG_VERBOSE("sending packet of death to cpu");
            uint64_t userdata = IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, 0);
            uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&port_pktin_soc[ctx->key->in_port].pktin_soc);
            action_userspace(ctx->actx, &userdata, sizeof(uint64_t), netlink_port);
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
            PIPELINE_STAT(VLAN_XLATE_MISS);
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
        PIPELINE_STAT(BAD_VLAN);
        mark_drop(ctx);
        return;
    }

    if (!check_vlan_membership(vlan_entry, ctx->key->in_port, NULL)) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", ctx->key->in_port, vlan_vid);
        PIPELINE_STAT(WRONG_VLAN);
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
        PIPELINE_STAT(ZERO_SRC_MAC);
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
            PIPELINE_STAT(SRC_DISCARD);
            mark_drop(ctx);
        } else if (!disable_src_mac_check) {
            if (src_l2_entry->value.lag != ctx->ingress_lag) {
                AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
                PIPELINE_STAT(STATION_MOVE);
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE, port_pktin_soc[ctx->key->in_port].pktin_soc);
                mark_drop(ctx);
            }
        }
    } else {
        if (!disable_src_mac_check) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            PIPELINE_STAT(NEW_HOST);
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_NEW_HOST, port_pktin_soc[ctx->key->in_port].pktin_soc);
            mark_drop(ctx);
        }
    }

    /* ARP offload */
    if (ctx->key->ethertype == htons(0x0806)) {
        if (port_entry->value.arp_offload) {
            AIM_LOG_VERBOSE("sending ARP packet to agent");
            PIPELINE_STAT(ARP_OFFLOAD);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP, port_pktin_soc[ctx->key->in_port].pktin_soc);
            /* Continue forwarding packet */
        }

        if (pipeline_bvs_table_arp_offload_lookup(
                ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip))) {
            AIM_LOG_VERBOSE("trapping ARP packet to VLAN %u IP %{ipv4a}", ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip));
            PIPELINE_STAT(ARP_OFFLOAD_TRAP);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP_TARGET, port_pktin_soc[ctx->key->in_port].pktin_soc);
            mark_drop(ctx);
            process_pktin(ctx);
            return;
        }
    }

    /* DHCP offload */
    if (port_entry->value.dhcp_offload) {
        if (ctx->key->ethertype == htons(0x0800) && ctx->key->ipv4.ipv4_proto == 17 &&
                (ctx->key->udp.udp_dst == htons(67) && ctx->key->udp.udp_src == htons(68)) &&
                !memcmp(ctx->key->ethernet.eth_dst, &broadcast_mac, OF_MAC_ADDR_BYTES)) {
            AIM_LOG_VERBOSE("sending DHCP packet to agent");
            PIPELINE_STAT(DHCP_OFFLOAD);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_DHCP, port_pktin_soc[ctx->key->in_port].pktin_soc);
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
        PIPELINE_STAT(DESTINATION_LOOKUP_FAILURE);

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
        PIPELINE_STAT(DST_DISCARD);
        mark_drop(ctx);
    } else {
        AIM_LOG_VERBOSE("hit in destination l2table lookup, lag %s", lag_name(dst_l2_entry->value.lag));
    }

    process_debug(ctx);
    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    if (process_floating_ip(ctx)) {
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(dst_l2_entry->value.lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        PIPELINE_STAT(EMPTY_LAG);
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

    PIPELINE_STAT(L3);

    if (bad_ttl) {
        AIM_LOG_VERBOSE("sending TTL expired packet to agent");
        PIPELINE_STAT(BAD_TTL);
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_TTL_EXPIRED, port_pktin_soc[ctx->key->in_port].pktin_soc);
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
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_CPU, port_pktin_soc[ctx->key->in_port].pktin_soc);
    }

    if (acl_cpu) {
        AIM_LOG_VERBOSE("Ingress ACL copy to CPU");
        mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_INGRESS_ACL, debug_acl_pktin_soc);
    }

    if (l3_cpu || acl_cpu) {
        if (drop) {
            AIM_LOG_VERBOSE("L3 drop");
            PIPELINE_STAT(L3_DROP);
            mark_drop(ctx);
        } else if (!valid_next_hop) {
            AIM_LOG_VERBOSE("L3 null route");
            PIPELINE_STAT(L3_NULL_ROUTE);
            mark_drop(ctx);
        }
    } else {
        if (drop) {
            AIM_LOG_VERBOSE("L3 drop");
            PIPELINE_STAT(L3_DROP);
            mark_drop(ctx);
        } else if (!hit) {
            AIM_LOG_VERBOSE("L3 miss");
            PIPELINE_STAT(L3_MISS);
            mark_drop(ctx);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_MISS, port_pktin_soc[ctx->key->in_port].pktin_soc);
        } else if (!valid_next_hop) {
            AIM_LOG_VERBOSE("L3 null route");
            PIPELINE_STAT(L3_NULL_ROUTE);
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
            PIPELINE_STAT(EMPTY_ECMP);
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

    if (next_hop->type == NEXT_HOP_TYPE_LAG) {
        ctx->internal_vlan_vid = next_hop->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
        action_set_eth_src(ctx->actx, next_hop->new_eth_src);
        action_set_eth_dst(ctx->actx, next_hop->new_eth_dst);
        action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl - 1);
        ctx->key->ipv4.ipv4_ttl--;
        memcpy(ctx->key->ethernet.eth_dst, &next_hop->new_eth_dst.addr, OF_MAC_ADDR_BYTES);
    }

    if (process_floating_ip(ctx)) {
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(next_hop->lag, ctx->hash);
    if (lag_bucket == NULL) {
        AIM_LOG_VERBOSE("empty LAG");
        PIPELINE_STAT(EMPTY_LAG);
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

    if (debug_entry->value.lag != NULL) {
        AIM_LOG_VERBOSE("using LAG %s from the debug table", debug_entry->value.lag->key.name);
        PIPELINE_STAT(DEBUG_REDIRECT);

        struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(debug_entry->value.lag, ctx->hash);
        if (lag_bucket == NULL) {
            AIM_LOG_VERBOSE("empty LAG");
            PIPELINE_STAT(EMPTY_LAG);
            return;
        }

        AIM_LOG_VERBOSE("selected LAG port %u", lag_bucket->port_no);

        process_egress(ctx, lag_bucket->port_no, false);

        mark_drop(ctx);
    }

    if (debug_entry->value.cpu) {
        if (!(ctx->pktin_metadata & (OFP_BSN_PKTIN_FLAG_ARP|
                                     OFP_BSN_PKTIN_FLAG_DHCP|
                                     OFP_BSN_PKTIN_FLAG_STATION_MOVE))) {
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_DEBUG, debug_acl_pktin_soc);
        }
    }

    if (debug_entry->value.drop) {
        PIPELINE_STAT(DEBUG_DROP);
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
        PIPELINE_STAT(EGRESS_BAD_VLAN);
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

    action_set_priority(ctx->actx, ctx->skb_priority);
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
            PIPELINE_STAT(EMPTY_LAG);
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
        PIPELINE_STAT(EMPTY_LAG);
        return;
    }

    AIM_LOG_VERBOSE("Selected LAG port %u", lag_bucket->port_no);

    if (span->value.vlan_vid != VLAN_INVALID) {
        AIM_LOG_VERBOSE("Pushing tag vlan_vid=%u", span->value.vlan_vid);
        action_push_vlan_raw(ctx->actx, span->value.vlan_vid|VLAN_CFI_BIT);
    }

    action_set_priority(ctx->actx, QUEUE_PRIORITY_SPAN);
    action_output(ctx->actx, lag_bucket->port_no);

    if (span->value.vlan_vid != VLAN_INVALID) {
        action_pop_vlan_raw(ctx->actx);
    }
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
        .ingress_port_group_id = ctx->ingress_port_group_id,
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
mark_pktin_agent(struct ctx *ctx, uint64_t flag, struct ind_ovs_pktin_socket pktin_soc)
{
    ctx->pktin_agent = true;
    ctx->pktin_metadata |= flag;
    ctx->pktin_soc = pktin_soc;
}

static void
mark_pktin_controller(struct ctx *ctx, uint64_t flag, struct ind_ovs_pktin_socket pktin_soc)
{
    ctx->pktin_controller = true;
    ctx->pktin_metadata |= flag;
    ctx->pktin_soc = pktin_soc;
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
        uint64_t userdata = IVS_PKTIN_USERDATA(reason, ctx->pktin_metadata);
        uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&ctx->pktin_soc);
        action_userspace(ctx->actx, &userdata, sizeof(uint64_t), netlink_port);
    }
}

/* Returns true if it consumes the packet */
static bool
process_floating_ip(struct ctx *ctx)
{
    struct floating_ip_forward_entry *floating_ip_forward_entry =
        pipeline_bvs_table_floating_ip_forward_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_src), ctx->key->ethernet.eth_dst);
    if (floating_ip_forward_entry) {
        PIPELINE_STAT(FLOATING_IP_FORWARD);
        struct floating_ip_forward_value *v = &floating_ip_forward_entry->value;
        of_mac_addr_t new_eth_dst = v->new_eth_dst;

        if (((v->new_ipv4_src ^ ntohl(ctx->key->ipv4.ipv4_dst)) & v->ipv4_netmask) == 0) {
            AIM_LOG_VERBOSE("Checking arp_cache table");
            struct arp_cache_entry *arp_cache_entry =
                pipeline_bvs_table_arp_cache_lookup(v->new_vlan_vid,
                                                    ntohl(ctx->key->ipv4.ipv4_dst));
            if (!arp_cache_entry) {
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_ARP_CACHE, port_pktin_soc[ctx->key->in_port].pktin_soc);
                process_pktin(ctx);
                return true;
            }

            new_eth_dst = arp_cache_entry->value.mac;
        }

        ctx->internal_vlan_vid = v->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, v->new_vlan_vid);
        action_set_eth_src(ctx->actx, v->new_eth_src);
        action_set_eth_dst(ctx->actx, new_eth_dst);
        action_set_ipv4_src(ctx->actx, v->new_ipv4_src);

        ctx->key->vlan = htons(VLAN_TCI_WITH_CFI(v->new_vlan_vid | VLAN_CFI_BIT, VLAN_PCP(ntohs(ctx->key->vlan))));
        memcpy(ctx->key->ethernet.eth_src, &v->new_eth_src, OF_MAC_ADDR_BYTES);
        memcpy(ctx->key->ethernet.eth_dst, &new_eth_dst, OF_MAC_ADDR_BYTES);
        ctx->key->ipv4.ipv4_src = htonl(v->new_ipv4_src);

        ctx->key->in_port = OVSP_LOCAL;
        process_l2(ctx);
        return true;
    }

    struct floating_ip_reverse_entry *floating_ip_reverse_entry =
        pipeline_bvs_table_floating_ip_reverse_lookup(
            ctx->internal_vlan_vid, ntohl(ctx->key->ipv4.ipv4_dst), ctx->key->ethernet.eth_dst);
    if (floating_ip_reverse_entry) {
        PIPELINE_STAT(FLOATING_IP_REVERSE);
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
        return true;
    }

    return false;
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
