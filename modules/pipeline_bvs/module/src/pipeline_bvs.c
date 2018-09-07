/****************************************************************
 *
 *        Copyright 2013-2016, Big Switch Networks, Inc.
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
static void process_multicast(struct ctx *ctx);
static void process_debug(struct ctx *ctx);
static void process_egress(struct ctx *ctx, uint32_t out_port, bool l3);
static bool check_vlan_membership(struct vlan_entry *vlan_entry, uint32_t in_port, bool *tagged);
static void flood_vlan(struct ctx *ctx);
static bool check_flood(struct ctx *ctx, struct lag_group *lag);
static void span(struct ctx *ctx, struct span_group *span);
static struct debug_gen_key make_debug_gen_key(struct ctx *ctx);
static struct debug_key make_debug_key(struct ctx *ctx);
static struct vlan_acl_key make_vlan_acl_key(struct ctx *ctx);
static struct ingress_acl_key make_ingress_acl_key(struct ctx *ctx);
static uint32_t group_to_table_id(uint32_t group_id);
static void mark_pktin_agent(struct ctx *ctx, uint64_t flag);
static void mark_pktin_controller(struct ctx *ctx, uint64_t flag);
static void mark_drop(struct ctx *ctx);
static void process_pktin(struct ctx *ctx);
static bool process_floating_ip(struct ctx *ctx);
static void trace_packet_headers(struct ctx *ctx);

enum pipeline_bvs_version version;

static uint32_t port_sampling_rate[SLSHARED_CONFIG_OF_PORT_MAX+1];

static int vlan_pcp_to_queue[8] = {QUEUE_PRIORITY_VLAN_PRIO_0_1,
                                   QUEUE_PRIORITY_VLAN_PRIO_0_1,
                                   QUEUE_PRIORITY_VLAN_PRIO_2_3,
                                   QUEUE_PRIORITY_VLAN_PRIO_2_3,
                                   QUEUE_PRIORITY_VLAN_PRIO_4_5,
                                   QUEUE_PRIORITY_VLAN_PRIO_4_5,
                                   QUEUE_PRIORITY_VLAN_PRIO_6_7,
                                   QUEUE_PRIORITY_VLAN_PRIO_6_7};

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
    } else if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
        return -997;
    } else if (table_id == pipeline_bvs_table_priority_to_pcp_profile_id ||
               table_id == pipeline_bvs_table_dscp_to_priority_profile_id) {
        return -996;
    } else if (table_id == pipeline_bvs_table_port_block_id) {
        return 1000;
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

static void
increment_tx_port_counters(of_port_no_t port_no, struct ctx *ctx)
{
    struct ind_ovs_port_counters *port_counters = ind_ovs_port_stats_select(port_no);
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
    if (port_no == OF_PORT_DEST_LOCAL) {
        port_no = OVSP_LOCAL;
    }

    if (reason == OF_PORT_CHANGE_REASON_ADD) {
        pipeline_bvs_port_pktin_socket_register(port_no);

        /* Use tc to set up queues for this port */
        of_port_name_t if_name;
        of_port_desc_name_get(&port_desc, &if_name);
        pipeline_bvs_setup_tc(if_name, port_no);
    } else if (reason == OF_PORT_CHANGE_REASON_DELETE) {
        pipeline_bvs_port_pktin_socket_unregister(port_no);
    } else if (reason == OF_PORT_CHANGE_REASON_MODIFY) {
        uint32_t state;
        of_port_desc_state_get(&port_desc, &state);
        if ((state & OF_PORT_STATE_FLAG_LINK_DOWN) &&
                pipeline_bvs_table_port_block_get_inuse(port_no)) {
            pipeline_bvs_table_port_block_block(port_no);
        }
    }

    /* HACK update generation ID property */
    if (port_status->version >= OF_VERSION_1_4) {
        of_list_port_desc_prop_t props;
        of_port_desc_properties_bind(&port_desc, &props);
        of_port_desc_prop_t prop;
        int rv;
        OF_LIST_PORT_DESC_PROP_ITER(&props, &prop, rv) {
            if (prop.object_id == OF_PORT_DESC_PROP_BSN_GENERATION_ID) {
                of_port_desc_prop_bsn_generation_id_generation_id_set(&prop,
                    pipeline_bvs_table_port_block_get_switch_generation_id(port_no));
            }
        }
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
    pipeline_bvs_table_priority_to_queue_register();
    pipeline_bvs_qos_register();
    pipeline_bvs_table_fspan_vlan_register();
    pipeline_bvs_table_port_block_register();
    pipeline_bvs_table_multicast_vlan_register();
    pipeline_bvs_table_multicast_replication_group_register();
    pipeline_bvs_table_multicast_replication_register();
    pipeline_bvs_table_ipv4_multicast_register();
    pipeline_bvs_table_port_multicast_register();
    pipeline_bvs_table_vlan_xlate2_register();
    pipeline_bvs_table_port_features_register();
    pipeline_bvs_table_priority_to_pcp_profile_register();
    pipeline_bvs_table_dscp_to_priority_profile_register();
    pipeline_bvs_table_port_qos_register();
    pipeline_bvs_table_debug_gen_register();
    pipeline_bvs_table_stub_register();
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
    pipeline_bvs_table_priority_to_queue_unregister();
    pipeline_bvs_table_fspan_vlan_unregister();
    pipeline_bvs_table_port_block_unregister();
    pipeline_bvs_table_multicast_vlan_unregister();
    pipeline_bvs_table_ipv4_multicast_unregister();
    pipeline_bvs_table_multicast_replication_unregister();
    pipeline_bvs_table_multicast_replication_group_unregister();
    pipeline_bvs_table_port_multicast_unregister();
    pipeline_bvs_table_vlan_xlate2_unregister();
    pipeline_bvs_table_port_features_unregister();
    pipeline_bvs_table_priority_to_pcp_profile_unregister();
    pipeline_bvs_table_dscp_to_priority_profile_unregister();
    pipeline_bvs_table_port_qos_unregister();
    pipeline_bvs_table_debug_gen_unregister();
    pipeline_bvs_table_stub_unregister();
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
    trace_packet_headers(ctx);

    ctx->recursion_depth++;
    if (ctx->recursion_depth > 10) {
        AIM_LOG_INTERNAL("Exceeded max recursion depth");
        return;
    }

    ctx->original_vlan_vid = VLAN_VID(ntohs(ctx->key->vlan));
    /* Extract skb_priority only for cpu generated packets */
    if (ctx->key->in_port == OVSP_LOCAL) {
        ctx->skb_priority = ctx->key->priority;
    }

    /* Ingress mirror */
    struct ingress_mirror_entry *ingress_mirror_entry =
        pipeline_bvs_table_ingress_mirror_lookup(ctx->key->in_port);
    if (ingress_mirror_entry) {
        span(ctx, ingress_mirror_entry->value.span);
    }

    if (ctx->key->in_port <= SLSHARED_CONFIG_OF_PORT_MAX &&
        port_sampling_rate[ctx->key->in_port]) {
        uint64_t userdata = IVS_PKTIN_USERDATA(0, ctx->original_vlan_vid, OFP_BSN_PKTIN_FLAG_SFLOW);
        struct ind_ovs_pktin_socket *pktin_soc = pipeline_bvs_get_pktin_socket(ctx->key->in_port, userdata);
        uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(pktin_soc);
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
                packet_trace("dropping CDP packet");
            } else {
                packet_trace("sending CDP packet directly to controller");
                mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
            }
            PIPELINE_STAT(PDU);
            mark_drop(ctx);
        } else {
            packet_trace("sending ethertype %#x directly to controller", ntohs(ctx->key->ethertype));
            PIPELINE_STAT(PDU);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
            mark_drop(ctx);
        }
    }

    if (!memcmp(ctx->key->ethernet.eth_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        packet_trace("sending slow protocols packet directly to controller");
        PIPELINE_STAT(PDU);
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
        PIPELINE_STAT(BAD_PORT);
        return;
    }

    ctx->ingress_lag_id = port_entry->value.lag_id;
    ctx->ingress_lag = port_entry->value.ingress_lag;
    ctx->ingress_port_group_id = port_entry->value.ingress_port_group_id;

    if (packet_of_death) {
        PIPELINE_STAT(PACKET_OF_DEATH);
        if (port_entry->value.packet_of_death) {
            packet_trace("sending packet of death to cpu");
            uint64_t userdata = IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, ctx->original_vlan_vid, 0);
            struct ind_ovs_pktin_socket *pktin_soc = pipeline_bvs_get_pktin_socket(ctx->key->in_port, userdata);
            uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(pktin_soc);
            action_userspace(ctx->actx, &userdata, sizeof(uint64_t), netlink_port);
        } else {
            packet_trace("ignoring packet of death on not-allowed port");
        }
        return;
    }

    uint16_t tag = VLAN_VID(ntohs(ctx->key->vlan));
    uint16_t vlan_vid;
    uint32_t internal_priority = INTERNAL_PRIORITY_INVALID;

    if (!(ctx->key->vlan & htons(VLAN_CFI_BIT))) {
        packet_trace("Using VLAN from port table");
        vlan_vid = port_entry->value.default_vlan_vid;
        action_push_vlan(ctx->actx);
        action_set_vlan_vid(ctx->actx, vlan_vid);
        internal_priority = port_entry->value.internal_priority;
    } else {
        struct vlan_xlate_entry *vlan_xlate_entry = NULL;
        struct vlan_xlate2_entry *vlan_xlate2_entry = NULL;

        if (port_entry->value.vlan_xlate_port_group_id != -1) {
            vlan_xlate_entry = pipeline_bvs_table_vlan_xlate_lookup(port_entry->value.vlan_xlate_port_group_id, tag);
        } else {
            vlan_xlate2_entry = pipeline_bvs_table_vlan_xlate2_lookup(port_entry->value.ingress_lag, tag);
        }

        if (vlan_xlate_entry) {
            packet_trace("Using VLAN from vlan_xlate");
            vlan_vid = vlan_xlate_entry->value.new_vlan_vid;
            action_set_vlan_vid(ctx->actx, vlan_vid);
            internal_priority = vlan_xlate_entry->value.internal_priority;
        } else if (vlan_xlate2_entry) {
            packet_trace("Using VLAN from vlan_xlate2");
            vlan_vid = vlan_xlate2_entry->value.new_vlan_vid;
            action_set_vlan_vid(ctx->actx, vlan_vid);
            internal_priority = vlan_xlate2_entry->value.internal_priority;
        } else if (port_entry->value.require_vlan_xlate) {
            packet_trace("vlan_xlate required and missed, dropping");
            PIPELINE_STAT(VLAN_XLATE_MISS);
            mark_drop(ctx);
            process_debug(ctx);
            process_pktin(ctx);
            return;
        } else {
            packet_trace("Using VLAN from packet");
            vlan_vid = tag;
            internal_priority = VLAN_PCP(ntohs(ctx->key->vlan));
        }
    }

    struct port_qos_entry *port_qos = pipeline_bvs_table_port_qos_lookup(ctx->key->in_port);
    if (port_qos && port_qos->value.dscp_profile) {
        if (ctx->key->ethertype == htons(ETH_P_IP) || ctx->key->ethertype == htons(ETH_P_IPV6)) {
            uint8_t dscp = (ctx->key->ethertype == htons(ETH_P_IP)) ?
                           (ctx->key->ipv4.ipv4_tos >> 2) : (ctx->key->ipv6.ipv6_tclass >> 2);

            internal_priority = port_qos->value.dscp_profile->value.buckets[dscp].qos_priority;
        }
    }

    ctx->internal_vlan_vid = vlan_vid;
    ctx->cur_tag = vlan_vid;
    ctx->internal_priority = internal_priority;

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
        packet_trace("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        PIPELINE_STAT(BAD_VLAN);
        pipeline_add_stats(ctx->stats, &port_counters->rx_bad_vlan_stats_handle);
        mark_drop(ctx);
        process_debug(ctx);
        process_pktin(ctx);
        return;
    }

    if (!check_vlan_membership(vlan_entry, ctx->key->in_port, NULL)) {
        packet_trace("port %u not allowed on vlan %u", ctx->key->in_port, vlan_vid);
        PIPELINE_STAT(WRONG_VLAN);
        mark_drop(ctx);
        return;
    }

    if (!port_entry->value.disable_vlan_counters) {
        pipeline_add_stats(ctx->stats, ind_ovs_rx_vlan_stats_select(vlan_vid));
    }

    if (!vlan_acl_entry) {
        packet_trace("VLAN %u: vrf=%u", vlan_vid, vlan_entry->value.vrf);
        ctx->vrf = vlan_entry->value.vrf;
        ctx->l3_interface_class_id = vlan_entry->value.l3_interface_class_id;
    }

    if (!memcmp(ctx->key->ethernet.eth_src, &zero_mac, OF_MAC_ADDR_BYTES)) {
        packet_trace("L2 source zero, discarding");
        PIPELINE_STAT(ZERO_SRC_MAC);
        mark_drop(ctx);
        return;
    }

    if (!memcmp(ctx->key->ethernet.eth_dst, &zero_mac, OF_MAC_ADDR_BYTES)) {
        packet_trace("L2 destination zero, discarding");
        mark_drop(ctx);
        return;
    }

    /* Source lookup */
    struct l2_entry *src_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, ctx->key->ethernet.eth_src, false);

    bool disable_src_mac_check =
        port_entry->value.disable_src_mac_check &&
            !pipeline_bvs_table_source_miss_override_lookup(vlan_vid, ctx->key->in_port);

    if (src_l2_entry) {
        pipeline_add_stats(ctx->stats, &src_l2_entry->stats_handle);

        if (src_l2_entry->value.lag == NULL) {
            packet_trace("L2 source discard");
            PIPELINE_STAT(SRC_DISCARD);
            mark_drop(ctx);
        } else if (!disable_src_mac_check) {
            if (src_l2_entry->value.lag != ctx->ingress_lag) {
                packet_trace("incorrect lag_id in source l2table lookup (station move)");
                PIPELINE_STAT(STATION_MOVE);
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_STATION_MOVE);
                mark_drop(ctx);
            }
        }
    } else {
        if (!disable_src_mac_check) {
            packet_trace("miss in source l2table lookup (new host)");
            PIPELINE_STAT(NEW_HOST);
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_NEW_HOST);
            mark_drop(ctx);
        }
    }

    /* ARP offload */
    if (ctx->key->ethertype == htons(0x0806)) {
        if (port_entry->value.arp_offload) {
            packet_trace("sending ARP packet to agent");
            PIPELINE_STAT(ARP_OFFLOAD);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP);
            /* Continue forwarding packet */
        }

        if (pipeline_bvs_table_arp_offload_lookup(
                ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip))) {
            packet_trace("trapping ARP packet to VLAN %u IP %{ipv4a}", ctx->internal_vlan_vid, ntohl(ctx->key->arp.arp_tip));
            PIPELINE_STAT(ARP_OFFLOAD_TRAP);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP_TARGET);
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
            packet_trace("sending DHCP packet to agent");
            PIPELINE_STAT(DHCP_OFFLOAD);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_DHCP);
        }
    }

    /* ICMPv6 offload */
    struct port_features_entry *port_features_entry =
        pipeline_bvs_table_port_features_lookup(ctx->key->in_port);
    bool ndp_offload = port_features_entry && port_features_entry->value.ndp_offload;

    /* ICMPv6 type NDP RS, RA, NS and NA packets */
    if (ctx->key->ethertype == htons(ETH_P_IPV6) &&
        ctx->key->ipv6.ipv6_proto == 58 &&
        ctx->key->icmpv6.icmpv6_type >= ICMPV6_TYPE_RS &&
        ctx->key->icmpv6.icmpv6_type <= ICMPV6_TYPE_NA) {
        if (ndp_offload) {
            packet_trace("sending ICMPV6 NDP packet to agent");
            PIPELINE_STAT(ICMPV6_OFFLOAD);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ICMPV6);
        }
    }

    /* Check for broadcast/multicast */
    if (ctx->key->ethernet.eth_dst[0] & 1) {
        process_debug(ctx);
        process_pktin(ctx);

        if (ctx->drop) {
            return;
        }

        if (!memcmp(ctx->key->ethernet.eth_dst, &broadcast_mac, OF_MAC_ADDR_BYTES)) {
            flood_vlan(ctx);
        } else {
            process_multicast(ctx);
        }

        return;
    }

    if (ctx->pktin_metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST) {
        process_debug(ctx);
        process_pktin(ctx);
        return;
    }

    if (ctx->key->ethertype == htons(ETH_P_IP) || ctx->key->ethertype == htons(ETH_P_IPV6)) {
        struct my_station_entry *my_station_entry =
            pipeline_bvs_table_my_station_lookup(ctx->key->ethernet.eth_dst, ctx->internal_vlan_vid);
        if (my_station_entry && !my_station_entry->value.disable_l3) {
            process_l3(ctx);
            return;
        }
    }

    /* Destination lookup */
    struct l2_entry *dst_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, ctx->key->ethernet.eth_dst, true);
    if (!dst_l2_entry) {
        packet_trace("miss in destination l2table lookup (destination lookup failure)");
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
        packet_trace("hit in destination l2table lookup, discard");
        PIPELINE_STAT(DST_DISCARD);
        mark_drop(ctx);
    } else {
        packet_trace("hit in destination l2table lookup, lag %s", lag_name(dst_l2_entry->value.lag));
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
        packet_trace("empty LAG");
        PIPELINE_STAT(EMPTY_LAG);
        return;
    }

    packet_trace("selected LAG port %u", lag_bucket->port_no);

    process_egress(ctx, lag_bucket->port_no, false);
}

static void
process_l3(struct ctx *ctx)
{
    struct next_hop *next_hop = NULL;
    bool l3_cpu = false;
    bool drop = false;
    bool bad_ttl = false;
    of_port_no_t acl_cpu_port = 0;

    if (ctx->key->ethertype == htons(ETH_P_IPV6)) {
        bad_ttl = ctx->key->ipv6.ipv6_hlimit <= 1;
    } else {
        bad_ttl = ctx->key->ipv4.ipv4_ttl <= 1;
    }

    PIPELINE_STAT(L3);

    if (bad_ttl) {
        packet_trace("sending TTL expired packet to agent");
        PIPELINE_STAT(BAD_TTL);
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_TTL_EXPIRED);
        mark_drop(ctx);
        process_debug(ctx);
        process_pktin(ctx);
        return;
    } else {
        struct l3_host_route_entry *l3_host_route_entry;

        if (ctx->key->ethertype == htons(ETH_P_IPV6)) {
            l3_host_route_entry = pipeline_bvs_table_l3_host_route_ipv6_lookup(ctx->vrf, ctx->key->ipv6.ipv6_dst);
        } else {
            l3_host_route_entry = pipeline_bvs_table_l3_host_route_ipv4_lookup(ctx->vrf, ctx->key->ipv4.ipv4_dst);
        }

        if (l3_host_route_entry != NULL) {
            next_hop = &l3_host_route_entry->value.next_hop;
            l3_cpu = l3_host_route_entry->value.cpu;
        } else {
            struct l3_cidr_route_entry *l3_cidr_route_entry;

            if (ctx->key->ethertype == htons(ETH_P_IPV6)) {
                l3_cidr_route_entry = pipeline_bvs_table_l3_cidr_route_ipv6_lookup(ctx->vrf, ctx->key->ipv6.ipv6_dst);
            } else {
                l3_cidr_route_entry = pipeline_bvs_table_l3_cidr_route_ipv4_lookup(ctx->vrf, ctx->key->ipv4.ipv4_dst);
            }

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
        acl_cpu_port = ingress_acl_entry->value.cpu_port;
        if (ingress_acl_entry->value.next_hop.type != NEXT_HOP_TYPE_NULL) {
            next_hop = &ingress_acl_entry->value.next_hop;
        }
    }

    bool hit = next_hop != NULL;
    bool valid_next_hop = next_hop != NULL && next_hop->type != NEXT_HOP_TYPE_NULL;

    if (l3_cpu) {
        packet_trace("L3 copy to CPU");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_CPU);
    }

    if (acl_cpu_port == OF_PORT_DEST_CONTROLLER) {
        packet_trace("Ingress ACL copy to CPU, Controller");
        mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_INGRESS_ACL);
    } else if (acl_cpu_port == OF_PORT_DEST_LOCAL) {
        packet_trace("Ingress ACL copy to CPU");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_INGRESS_ACL_LOCAL);
    }

    if (l3_cpu || acl_cpu_port) {
        if (drop) {
            packet_trace("L3 drop");
            PIPELINE_STAT(L3_DROP);
            mark_drop(ctx);
        } else if (!valid_next_hop) {
            packet_trace("L3 null route");
            PIPELINE_STAT(L3_NULL_ROUTE);
            mark_drop(ctx);
        }
    } else {
        if (drop) {
            packet_trace("L3 drop");
            PIPELINE_STAT(L3_DROP);
            mark_drop(ctx);
        } else if (!hit) {
            packet_trace("L3 miss");
            PIPELINE_STAT(L3_MISS);
            mark_drop(ctx);
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_MISS);
        } else if (!valid_next_hop) {
            packet_trace("L3 null route");
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
            packet_trace("empty ecmp group %d", next_hop->ecmp->id);
            PIPELINE_STAT(EMPTY_ECMP);
            return;
        }

        next_hop = &ecmp_bucket->next_hop;
    }

    if (next_hop->type == NEXT_HOP_TYPE_LAG) {
        packet_trace("next-hop: eth_src=%{mac} eth_dst=%{mac} vlan=%u lag=%s",
                     next_hop->new_eth_src.addr, next_hop->new_eth_dst.addr,
                     next_hop->new_vlan_vid, lag_name(next_hop->lag));
    } else if (next_hop->type == NEXT_HOP_TYPE_LAG_NOREWRITE) {
        packet_trace("next-hop: lag=%s", lag_name(next_hop->lag));
    } else {
        AIM_DIE("Unexpected next hop type %d", next_hop->type);
    }

    if (next_hop->type == NEXT_HOP_TYPE_LAG) {
        ctx->internal_vlan_vid = next_hop->new_vlan_vid;
        action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
        action_set_eth_src(ctx->actx, next_hop->new_eth_src);
        action_set_eth_dst(ctx->actx, next_hop->new_eth_dst);
        if (ctx->key->ethertype == htons(ETH_P_IPV6)) {
            action_set_ipv6_ttl(ctx->actx, ctx->key->ipv6.ipv6_hlimit - 1);
            ctx->key->ipv6.ipv6_hlimit--;
        } else {
            action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl - 1);
            ctx->key->ipv4.ipv4_ttl--;
        }
        memcpy(ctx->key->ethernet.eth_dst, &next_hop->new_eth_dst.addr, OF_MAC_ADDR_BYTES);
    }

    if (process_floating_ip(ctx)) {
        return;
    }

    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(next_hop->lag, ctx->hash);
    if (lag_bucket == NULL) {
        packet_trace("empty LAG");
        PIPELINE_STAT(EMPTY_LAG);
        return;
    }

    packet_trace("selected LAG port %u", lag_bucket->port_no);

    process_egress(ctx, lag_bucket->port_no, true);
}

static bool
multicast_replication_lag_check(
    struct multicast_replication_group_entry *replication_group,
    struct lag_group *lag, bool l3)
{
    struct list_links *cur;
    LIST_FOREACH(&replication_group->members, cur) {
        struct multicast_replication_entry *replication =
            container_of(cur, links, struct multicast_replication_entry);
        if (replication->l3 != l3) {
            continue;
        } else if (replication->key.lag == lag) {
            return true;
        }
    }
    return false;
}

static void
process_multicast(struct ctx *ctx)
{
    packet_trace("Entering multicast processing");

    struct multicast_vlan_entry *multicast_vlan_entry =
        pipeline_bvs_table_multicast_vlan_lookup(ctx->internal_vlan_vid);
    struct port_multicast_entry *port_multicast_entry =
        pipeline_bvs_table_port_multicast_lookup(ctx->key->in_port);

    struct multicast_replication_group_entry *replication_group = NULL;
    bool igmp_snooping = multicast_vlan_entry && multicast_vlan_entry->value.igmp_snooping &&
        port_multicast_entry && port_multicast_entry->value.igmp_snooping;

    if (!multicast_vlan_entry) {
        packet_trace("Missed in multicast_vlan table, flooding");
        flood_vlan(ctx);
        return;
    }

    if (igmp_snooping && ctx->key->ipv4.ipv4_proto == 2) {
        packet_trace("Trapping and flood IGMP packet");
        flood_vlan(ctx);
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_IGMP);
        process_pktin(ctx);
        return;
    }

    if ((ntohl(ctx->key->ipv4.ipv4_dst) & 0xffffff00) == 0xe0000000) {
        if (igmp_snooping && ctx->key->ipv4.ipv4_proto == 103 && ntohl(ctx->key->ipv4.ipv4_dst) == 0xe000000d) {
            packet_trace("Copying PIM packet to the CPU");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PIM);
            process_pktin(ctx);
        } else if (igmp_snooping) {
            packet_trace("Copying reserved multicast IP packet to the CPU");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_MC_RESERVED);
            process_pktin(ctx);
        }
        packet_trace("Reserved multicast IP, flooding");
        flood_vlan(ctx);
        return;
    }

    if (!multicast_vlan_entry->value.igmp_snooping) {
        packet_trace("IGMP snooping disabled, flooding");
        flood_vlan(ctx);
        return;
    }

    replication_group = multicast_vlan_entry->value.default_replication_group;
    if (replication_group) {
        packet_trace("Default replication group is %s", replication_group->key.name);
    } else {
        packet_trace("No default replication group");
    }

    /* IPV4 multicast table lookup
     *  - L3 VLANs will use VRF, multicast group and src IP
     *    multicast_interface_id is used only by p-switch to RPF check.
     *  - L2 VLANs will use multicast_interface_id, multicast group and src IP
     */
    struct ipv4_multicast_entry *ipv4_multicast_entry = NULL;
    ipv4_multicast_entry = pipeline_bvs_table_ipv4_multicast_lookup(
        multicast_vlan_entry->value.l3_enabled ? 0 : multicast_vlan_entry->value.multicast_interface_id,
        ctx->vrf, ntohl(ctx->key->ipv4.ipv4_dst), ntohl(ctx->key->ipv4.ipv4_src));
    if (ipv4_multicast_entry) {
        replication_group = ipv4_multicast_entry->value.multicast_replication_group;
    }

    if (!replication_group) {
        packet_trace("No multicast replication group found");
        /* ctx->drop = true ? */
        return;
    }

    uint16_t orig_internal_vlan_vid = ctx->internal_vlan_vid;
    of_mac_addr_t orig_eth_src;
    memcpy(&orig_eth_src, ctx->key->ethernet.eth_src, ETH_ALEN);

    struct list_links *cur;
    LIST_FOREACH(&replication_group->members, cur) {
        struct multicast_replication_entry *replication =
            container_of(cur, links, struct multicast_replication_entry);

        if (!replication->l3) {
            if (multicast_replication_lag_check(replication_group, replication->key.lag, true)) {
                packet_trace("Skipping L2 replication with corresponding L3 replication entry");
                continue;
            }
        }

        if (!check_flood(ctx, replication->key.lag)) {
            packet_trace("LAG %s is not eligible for flooding", replication->key.lag->key.name);
            continue;
        }

        bool l3 = replication->l3 && replication->key.vlan_vid != orig_internal_vlan_vid;

        if (l3) {
            packet_trace("L3 multicast replication to VLAN %u LAG %s", replication->key.vlan_vid, replication->key.lag->key.name);

            ctx->internal_vlan_vid = replication->key.vlan_vid;
            action_set_eth_src(ctx->actx, replication->value.new_eth_src);

            /* TODO check TTL */
            action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl - 1);
            ctx->key->ipv4.ipv4_ttl--;
        } else {
            packet_trace("L2 multicast replication to LAG %s", replication->key.lag->key.name);

            if (replication->l3 && !multicast_replication_lag_check(replication_group, replication->key.lag, false)) {
                packet_trace("Skipping L2 replication without corresponding L2 replication entry");
            }

            ctx->internal_vlan_vid = orig_internal_vlan_vid;
            action_set_eth_src(ctx->actx, orig_eth_src);
        }

        struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(replication->key.lag, ctx->hash);
        if (lag_bucket == NULL) {
            packet_trace("empty LAG");
            PIPELINE_STAT(EMPTY_LAG);
            goto out;
        }

        packet_trace("selected LAG port %u", lag_bucket->port_no);

        struct port_entry *dst_port_entry = pipeline_bvs_table_port_lookup(lag_bucket->port_no);
        if (!dst_port_entry) {
            goto out;
        }

        if (dst_port_entry->value.lag_id != OF_GROUP_ANY &&
                dst_port_entry->value.ingress_lag == ctx->ingress_lag &&
                replication->key.vlan_vid == orig_internal_vlan_vid) {
            packet_trace("skipping ingress VLAN/LAG %u/%s", orig_internal_vlan_vid, lag_name(ctx->ingress_lag));
            goto out;
        }

        process_egress(ctx, lag_bucket->port_no, l3);

out:
        if (l3) {
            action_set_ipv4_ttl(ctx->actx, ctx->key->ipv4.ipv4_ttl + 1);
            ctx->key->ipv4.ipv4_ttl++;
        }
    }
}

static void
process_debug(struct ctx *ctx)
{
    struct stats_handle *stats_handle = NULL;
    struct span_group *span_gp = NULL;
    struct lag_group *lag = NULL;
    bool cpu = false;
    bool drop = false;

    struct debug_gen_key debug_gen_key = make_debug_gen_key(ctx);
    struct debug_gen_entry *debug_gen_entry =
        pipeline_bvs_table_debug_gen_lookup(&debug_gen_key);

    /* Look into debug flow table if no matching entry is found in debug gentable. */
    if (debug_gen_entry) {
        stats_handle = &debug_gen_entry->stats_handle;
        span_gp = debug_gen_entry->value.span;
        lag = debug_gen_entry->value.lag;
        drop = debug_gen_entry->value.drop;
        cpu = debug_gen_entry->value.cpu;
    } else {
        struct debug_key debug_key = make_debug_key(ctx);
        struct debug_entry *debug_entry =
            pipeline_bvs_table_debug_lookup(&debug_key);
        if (!debug_entry) {
            return;
        }

        stats_handle = &debug_entry->stats_handle;
        span_gp = debug_entry->value.span;
        lag = debug_entry->value.lag;
        drop = debug_entry->value.drop;
        cpu = debug_entry->value.cpu;
    }

    pipeline_add_stats(ctx->stats, stats_handle);

    if (span_gp != NULL) {
        if (ctx->original_vlan_vid != 0) {
            action_set_vlan_vid(ctx->actx, ctx->original_vlan_vid);
        } else {
            action_pop_vlan(ctx->actx);
        }
        span(ctx, span_gp);
        action_set_vlan_vid(ctx->actx, ctx->internal_vlan_vid);
    }

    if (lag != NULL) {
        packet_trace("using LAG %s from the debug table", lag->key.name);
        PIPELINE_STAT(DEBUG_REDIRECT);

        struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(lag, ctx->hash);
        if (lag_bucket == NULL) {
            packet_trace("empty LAG");
            PIPELINE_STAT(EMPTY_LAG);
            return;
        }

        packet_trace("selected LAG port %u", lag_bucket->port_no);

        process_egress(ctx, lag_bucket->port_no, false);

        mark_drop(ctx);
    }

    if (cpu) {
        if (!(ctx->pktin_metadata & (OFP_BSN_PKTIN_FLAG_ARP|
                                     OFP_BSN_PKTIN_FLAG_DHCP|
                                     OFP_BSN_PKTIN_FLAG_STATION_MOVE))) {
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_DEBUG);
        }
    }

    if (drop) {
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
        packet_trace("Packet routed to unconfigured vlan %u", ctx->internal_vlan_vid);
        PIPELINE_STAT(EGRESS_BAD_VLAN);
        return;
    }

    bool out_port_tagged;
    if (!check_vlan_membership(vlan_entry, out_port, &out_port_tagged)) {
        packet_trace("output port %u not allowed on vlan %u", out_port, ctx->internal_vlan_vid);
        return;
    }

    struct port_entry *dst_port_entry = pipeline_bvs_table_port_lookup(out_port);
    if (!dst_port_entry) {
        return;
    }

    if (!l3 && dst_port_entry->value.lag_id != OF_GROUP_ANY &&
            dst_port_entry->value.ingress_lag == ctx->ingress_lag) {
        packet_trace("skipping ingress LAG %s", lag_name(ctx->ingress_lag));
        return;
    }

    if (!dst_port_entry->value.disable_vlan_counters) {
        pipeline_add_stats(ctx->stats, ind_ovs_tx_vlan_stats_select(ctx->internal_vlan_vid));
    }

    increment_tx_port_counters(out_port, ctx);

    /* Egress VLAN translation */
    uint16_t tag = ctx->internal_vlan_vid;
    if (!out_port_tagged) {
        tag = 0;
    } else {
        struct egr_vlan_xlate_entry *egr_vlan_xlate_entry = NULL;
        if (dst_port_entry->value.vlan_xlate_port_group_id != -1) {
            egr_vlan_xlate_entry = pipeline_bvs_table_egr_vlan_xlate_lookup(dst_port_entry->value.vlan_xlate_port_group_id, 0, ctx->internal_vlan_vid);
        } else {
            egr_vlan_xlate_entry = pipeline_bvs_table_egr_vlan_xlate_lookup(0, out_port, ctx->internal_vlan_vid);
        }
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

    /* If skb_priority is already set in the packet, use that instead */
    if (!ctx->skb_priority) {
        if (ctx->internal_priority != INTERNAL_PRIORITY_INVALID) {
            struct priority_to_queue_entry *prio_to_queue_entry =
                pipeline_bvs_table_priority_to_queue_lookup(ctx->internal_priority);
            struct port_qos_entry *port_qos = pipeline_bvs_table_port_qos_lookup(out_port);
            if (prio_to_queue_entry) {
                ctx->skb_priority = prio_to_queue_entry->value.queue_id;

                if (tag != 0) {
                    if (port_qos && port_qos->value.priority_to_pcp_profile) {
                        action_set_vlan_pcp(ctx->actx, port_qos->value.priority_to_pcp_profile->value.buckets[ctx->internal_priority].vlan_pcp);
                    } else {
                        action_set_vlan_pcp(ctx->actx, ctx->internal_priority);
                    }
                }
            } else if (tag != 0) {
                /* Use vlan pcp to decide the skb_priority */
                ctx->skb_priority = vlan_pcp_to_queue[VLAN_PCP(ntohs(ctx->actx->current_key.vlan))];
            }
        }
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
            packet_trace("empty LAG %s", lag_name(lag));
            PIPELINE_STAT(EMPTY_LAG);
            continue;
        }
        packet_trace("selected LAG %s port %u", lag_name(lag), lag_bucket->port_no);

        process_egress(ctx, lag_bucket->port_no, false);
    }
}

static bool
check_flood(struct ctx *ctx, struct lag_group *lag)
{
    struct flood_key key = { .lag_id = ctx->ingress_lag_id };
    struct flood_entry *entry = pipeline_bvs_table_flood_lookup(&key);
    if (entry == NULL) {
        return false;
    }

    int i;
    for (i = 0; i < entry->value.num_lags; i++) {
        if (lag == entry->value.lags[i]) {
            return true;
        }
    }

    return false;
}

static void
span(struct ctx *ctx, struct span_group *span)
{
    struct lag_bucket *lag_bucket = pipeline_bvs_table_lag_select(span->value.lag, ctx->hash);
    if (lag_bucket == NULL) {
        packet_trace("empty LAG");
        PIPELINE_STAT(EMPTY_LAG);
        return;
    }

    packet_trace("Selected LAG port %u", lag_bucket->port_no);

    increment_tx_port_counters(lag_bucket->port_no, ctx);

    if (span->value.vlan_vid != VLAN_INVALID) {
        packet_trace("Pushing tag vlan_vid=%u", span->value.vlan_vid);
        action_push_vlan_raw(ctx->actx, span->value.vlan_vid|VLAN_CFI_BIT);
    }

    action_set_priority(ctx->actx, QUEUE_PRIORITY_SPAN);
    action_output(ctx->actx, lag_bucket->port_no);

    if (span->value.vlan_vid != VLAN_INVALID) {
        action_pop_vlan_raw(ctx->actx);
    }
}

static struct debug_gen_key
make_debug_gen_key(struct ctx *ctx)
{
    struct debug_gen_key key;

    AIM_ZERO(key);

    memcpy(&key.eth_src, ctx->key->ethernet.eth_src, OF_MAC_ADDR_BYTES);
    memcpy(&key.eth_dst, ctx->key->ethernet.eth_dst, OF_MAC_ADDR_BYTES);

    key.in_port = ctx->key->in_port;
    key.eth_type = ntohs(ctx->key->ethertype);
    key.vlan_vid = ctx->internal_vlan_vid;
    key.vrf = ctx->vrf;
    key.l3_src_class_id = ctx->l3_src_class_id;
    key.ingress_port_group_id = ctx->ingress_port_group_id;

    if (key.eth_type == ETH_P_IPV6) {
        memcpy(&key.ipv6_src, &ctx->key->ipv6.ipv6_src, sizeof(key.ipv6_src));
        memcpy(&key.ipv6_dst, &ctx->key->ipv6.ipv6_dst, sizeof(key.ipv6_dst));
        key.ip_proto = ctx->key->ipv6.ipv6_proto;
        key.dscp = ctx->key->ipv6.ipv6_tclass >> IP_DSCP_SHIFT;
        key.ecn = ctx->key->ipv6.ipv6_tclass & IP_ECN_MASK;
        key.ip_pkt = 1;
    } else if (key.eth_type == ETH_P_IP) {
        key.ipv4_src = ntohl(ctx->key->ipv4.ipv4_src);
        key.ipv4_dst = ntohl(ctx->key->ipv4.ipv4_dst);
        key.ip_proto = ctx->key->ipv4.ipv4_proto;
        key.dscp = ctx->key->ipv4.ipv4_tos >> IP_DSCP_SHIFT;
        key.ecn = ctx->key->ipv4.ipv4_tos & IP_ECN_MASK;
        key.ip_pkt = 1;
    }

    if (key.ip_proto == IPPROTO_TCP) {
        key.tcp_src = ntohs(ctx->key->tcp.tcp_src);
        key.tcp_dst = ntohs(ctx->key->tcp.tcp_dst);
    } else if (key.ip_proto == IPPROTO_UDP) {
        key.udp_src = ntohs(ctx->key->udp.udp_src);
        key.udp_dst = ntohs(ctx->key->udp.udp_dst);
    }

    return key;
}

static struct debug_key
make_debug_key(struct ctx *ctx)
{
    struct debug_key key = {
        .in_port = ctx->key->in_port,
        .eth_type = ntohs(ctx->key->ethertype),
        .vlan_vid = ctx->internal_vlan_vid,
        .vrf = ctx->vrf,
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
    struct ingress_acl_key key;

    AIM_ZERO(key);

    key.in_port = ctx->key->in_port;
    key.eth_type = ntohs(ctx->key->ethertype);
    key.vlan_vid = ctx->internal_vlan_vid;
    key.vrf = ctx->vrf;
    key.l3_interface_class_id = ctx->l3_interface_class_id;
    key.l3_src_class_id = ctx->l3_src_class_id;

    if (key.eth_type == ETH_P_IPV6) {
        key.ip_proto = ctx->key->ipv6.ipv6_proto;
        memcpy(&key.ipv6_src, &ctx->key->ipv6.ipv6_src, sizeof(key.ipv6_src));
        memcpy(&key.ipv6_dst, &ctx->key->ipv6.ipv6_dst, sizeof(key.ipv6_dst));
    } else {
        key.ipv4_src = ntohl(ctx->key->ipv4.ipv4_src);
        key.ipv4_dst = ntohl(ctx->key->ipv4.ipv4_dst);
        key.ip_proto = ctx->key->ipv4.ipv4_proto;
    }

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
        if ((ctx->original_vlan_vid & pipeline_bvs_fspan_vlan_vid_mask) == pipeline_bvs_fspan_vlan_vid) {
            packet_trace("Dropping packet-in on fabric-span VLAN");
            return;
        }
        uint8_t reason = ctx->pktin_controller ? OF_PACKET_IN_REASON_ACTION : OF_PACKET_IN_REASON_NO_MATCH;
        uint64_t userdata = IVS_PKTIN_USERDATA(reason, ctx->original_vlan_vid, ctx->pktin_metadata);
        struct ind_ovs_pktin_socket *pktin_soc = pipeline_bvs_get_pktin_socket(ctx->key->in_port, userdata);
        uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(pktin_soc);
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
            packet_trace("Checking arp_cache table");
            struct arp_cache_entry *arp_cache_entry =
                pipeline_bvs_table_arp_cache_lookup(v->new_vlan_vid,
                                                    ntohl(ctx->key->ipv4.ipv4_dst));
            if (!arp_cache_entry) {
                mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_ARP_CACHE);
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

static void
trace_packet_headers(struct ctx *ctx)
{
    if (!packet_trace_enabled) {
        return;
    }

    const struct ind_ovs_parsed_key *key = ctx->key;
    packet_trace("Headers:");
    packet_trace("  in_port %u priority %u", key->in_port, key->priority);
    packet_trace("  eth_src %{mac} eth_dst %{mac} eth_type 0x%04x", &key->ethernet.eth_src, &key->ethernet.eth_dst, ntohs(key->ethertype));
    if (key->vlan) {
        packet_trace("  vlan_vid %u vlan_pcp %u", VLAN_VID(ntohs(key->vlan)), VLAN_PCP(ntohs(key->vlan)));
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV4)) {
        packet_trace("  ipv4_src %{ipv4a} ipv4_dst %{ipv4a} ip_proto %u ip_tos %u ip_ttl %u ip_frag %u",
                     ntohl(key->ipv4.ipv4_src), ntohl(key->ipv4.ipv4_dst), key->ipv4.ipv4_proto, key->ipv4.ipv4_tos, key->ipv4.ipv4_ttl, key->ipv4.ipv4_frag);
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV6)) {
        packet_trace("  ipv6_src %{ipv6a} ipv6_dst %{ipv6a} ipv6_label %u ipv6_proto %u ipv6_tclass %u ipv6_hlimit %u ipv6_frag %u",
                     &key->ipv6.ipv6_src, &key->ipv6.ipv6_dst, key->ipv6.ipv6_label, key->ipv6.ipv6_proto, key->ipv6.ipv6_tclass, key->ipv6.ipv6_hlimit, key->ipv6.ipv6_frag);
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_TCP)) {
        packet_trace("  tcp_src %u tcp_dst %u", ntohs(key->tcp.tcp_src), ntohs(key->tcp.tcp_dst));
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_UDP)) {
        packet_trace("  udp_src %u udp_dst %u", ntohs(key->udp.udp_src), ntohs(key->udp.udp_dst));
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ICMP)) {
        packet_trace("  icmp_type %u icmp_code %u", key->icmp.icmp_type, key->icmp.icmp_code);
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ICMPV6)) {
        packet_trace("  icmpv6_type %u icmpv6_code %u", key->icmpv6.icmpv6_type, key->icmpv6.icmpv6_code);
    }
    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ARP)) {
        packet_trace("  arp_op %u arp_spa %{ipv4a} arp_tpa %{ipv4a} arp_sha %{mac} arp_tha %{mac}",
                     ntohs(key->arp.arp_op), ntohl(key->arp.arp_sip), ntohl(key->arp.arp_tip),
                     key->arp.arp_sha, key->arp.arp_tha);
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
    pipeline_register("bvs-1.0-ipv4-only", &pipeline_bvs_ops);
    pipeline_register("experimental", &pipeline_bvs_ops); /* For command-line compatibility */
}
