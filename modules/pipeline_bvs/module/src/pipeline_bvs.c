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

static const bool flood_on_dlf = true;
static const of_mac_addr_t slow_protocols_mac = { { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 } };
static const of_mac_addr_t packet_of_death_mac = { { 0x5C, 0x16, 0xC7, 0xFF, 0xFF, 0x04 } };
static const of_mac_addr_t cdp_mac = { { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc } };

static void process_l2(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint8_t ipv4_ttl);
static void process_l3(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint32_t ingress_lag_id, uint16_t orig_vlan_vid, uint8_t ttl);
static void process_debug(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint16_t orig_vlan_vid);
static void process_egress(struct ctx *ctx, uint32_t out_port, uint16_t vlan_vid, uint32_t ingress_lag_id, uint32_t l3_interface_class_id, bool l3);
static bool check_vlan_membership(struct vlan_entry *vlan_entry, uint32_t in_port, bool *tagged);
static void flood_vlan(struct ctx *ctx, uint16_t vlan_vid, uint32_t lag_id);
static void span(struct ctx *ctx, uint32_t span_id);
static indigo_error_t select_lag_port( uint32_t group_id, uint32_t hash, uint32_t *port_no);
static indigo_error_t select_ecmp_route(uint32_t group_id, uint32_t hash, struct next_hop **next_hop);
static indigo_error_t lookup_l3_route(uint32_t vrf, uint32_t ipv4_dst, struct next_hop **next_hop, bool *cpu);
static void lookup_debug(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint32_t *span_id, bool *cpu, bool *drop);
static struct vlan_acl_key make_vlan_acl_key(struct ind_ovs_cfr *cfr);
static void lookup_ingress_acl(struct ctx *ctx, struct ind_ovs_cfr *cfr, struct next_hop **next_hop, bool *cpu, bool *drop);
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
}

static void
pipeline_bvs_finish(void)
{
    indigo_cxn_async_channel_selector_unregister(pipeline_bvs_cxn_async_channel_selector);
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
}

static indigo_error_t
pipeline_bvs_process(struct ind_ovs_parsed_key *key,
                     struct pipeline_result *result)
{
    struct ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.result = result;

    struct ind_ovs_cfr cfr;
    ind_ovs_key_to_cfr(key, &cfr);

    ctx.hash = murmur_hash(&cfr, sizeof(cfr), 0);

    process_l2(&ctx, &cfr, key->ipv4.ipv4_ttl);

    return INDIGO_ERROR_NONE;
}

static void
process_l2(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint8_t ipv4_ttl)
{
    uint16_t orig_vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan));

    /* Ingress mirror */
    struct ingress_mirror_entry *ingress_mirror_entry =
        pipeline_bvs_table_ingress_mirror_lookup(cfr->in_port);
    if (ingress_mirror_entry) {
        span(ctx, ingress_mirror_entry->value.span_id);
    }

    bool packet_of_death = false;
    if (cfr->dl_type == htons(0x88cc)) {
        if (!memcmp(cfr->dl_src, packet_of_death_mac.addr, OF_MAC_ADDR_BYTES)) {
            packet_of_death = true;
        } else if (!memcmp(cfr->dl_dst, cdp_mac.addr, OF_MAC_ADDR_BYTES)) {
            AIM_LOG_VERBOSE("dropping CDP packet");
            mark_drop(ctx);
        } else {
            AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(cfr->dl_type));
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
            mark_drop(ctx);
        }
    }

    if (!memcmp(cfr->dl_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_VERBOSE("sending slow protocols packet directly to controller");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_PDU);
        mark_drop(ctx);
    }

    /* HACK early drop for PDUs */
    if (ctx->drop) {
        process_pktin(ctx);
        return;
    }

    struct port_entry *port_entry = pipeline_bvs_table_port_lookup(cfr->in_port);
    if (!port_entry) {
        return;
    }

    if (packet_of_death) {
        if (port_entry->value.packet_of_death) {
            AIM_LOG_VERBOSE("sending packet of death to cpu");
            pktin(ctx->result, OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH, 0);
        } else {
            AIM_LOG_VERBOSE("ignoring packet of death on not-allowed port");
        }
        return;
    }

    uint16_t vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan));

    struct vlan_acl_key vlan_acl_key = make_vlan_acl_key(cfr);
    struct vlan_acl_entry *vlan_acl_entry =
        pipeline_bvs_table_vlan_acl_lookup(&vlan_acl_key);
    if (vlan_acl_entry) {
        cfr->vrf = vlan_acl_entry->value.vrf;
        cfr->l3_interface_class_id = vlan_acl_entry->value.l3_interface_class_id;
        cfr->l3_src_class_id = vlan_acl_entry->value.l3_src_class_id;
    } else {
        if (cfr->dl_vlan & htons(VLAN_CFI_BIT)) {
            struct vlan_xlate_entry *vlan_xlate_entry =
                pipeline_bvs_table_vlan_xlate_lookup(port_entry->value.lag_id, vlan_vid);
            if (vlan_xlate_entry) {
                vlan_vid = vlan_xlate_entry->value.new_vlan_vid;
                set_vlan_vid(ctx->result, vlan_vid);
            }
        } else {
            vlan_vid = port_entry->value.default_vlan_vid;
            push_vlan(ctx->result, 0x8100);
            set_vlan_vid(ctx->result, vlan_vid);
        }
    }

    cfr->dl_vlan = htons(VLAN_TCI(vlan_vid, VLAN_PCP(ntohs(cfr->dl_vlan))) | VLAN_CFI_BIT);

    struct vlan_entry *vlan_entry = pipeline_bvs_table_vlan_lookup(vlan_vid);
    if (!vlan_entry) {
        AIM_LOG_VERBOSE("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        mark_drop(ctx);
        return;
    }

    if (!check_vlan_membership(vlan_entry, cfr->in_port, NULL)) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", cfr->in_port, vlan_vid);
        mark_drop(ctx);
        return;
    }

    if (!vlan_acl_entry) {
        AIM_LOG_VERBOSE("VLAN %u: vrf=%u", vlan_vid, vlan_entry->value.vrf);
        cfr->vrf = vlan_entry->value.vrf;
        cfr->l3_interface_class_id = vlan_entry->value.l3_interface_class_id;
    }

    /* Source lookup */
    struct l2_entry *src_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, cfr->dl_src);
    if (src_l2_entry) {
        apply_stats(ctx->result, &src_l2_entry->stats);

        if (src_l2_entry->value.lag_id == OF_GROUP_ANY) {
            AIM_LOG_VERBOSE("L2 source discard");
            mark_drop(ctx);
        } else if (!port_entry->value.disable_src_mac_check) {
            if (src_l2_entry->value.lag_id != OF_GROUP_ANY &&
                    src_l2_entry->value.lag_id != port_entry->value.lag_id) {
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
        if (cfr->dl_type == htons(0x0806)) {
            AIM_LOG_VERBOSE("sending ARP packet to agent");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_ARP);
            /* Continue forwarding packet */
        }
    }

    /* DHCP offload */
    if (port_entry->value.dhcp_offload) {
        if (cfr->dl_type == htons(0x0800) && cfr->nw_proto == 17 &&
                (cfr->tp_dst == htons(67) || cfr->tp_dst == htons(68))) {
            AIM_LOG_VERBOSE("sending DHCP packet to agent");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_DHCP);
            mark_drop(ctx);
        }
    }

    /* Check for broadcast/multicast */
    if (cfr->dl_dst[0] & 1) {
        process_debug(ctx, cfr, orig_vlan_vid);
        process_pktin(ctx);

        if (ctx->drop) {
            return;
        }

        flood_vlan(ctx, vlan_vid, port_entry->value.lag_id);

        return;
    }

    if (ctx->pktin_metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST) {
        process_debug(ctx, cfr, orig_vlan_vid);
        process_pktin(ctx);
        return;
    }

    if (pipeline_bvs_table_my_station_lookup(cfr->dl_dst)) {
        process_l3(ctx, cfr, port_entry->value.lag_id, orig_vlan_vid, ipv4_ttl);
        return;
    }

    /* Destination lookup */
    struct l2_entry *dst_l2_entry =
        pipeline_bvs_table_l2_lookup(vlan_vid, cfr->dl_dst);
    if (!dst_l2_entry) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");

        process_debug(ctx, cfr, orig_vlan_vid);
        process_pktin(ctx);

        if (ctx->drop) {
            return;
        }

        flood_vlan(ctx, vlan_vid, port_entry->value.lag_id);

        return;
    }

    AIM_LOG_VERBOSE("hit in destination l2table lookup, lag %u", dst_l2_entry->value.lag_id);

    if (dst_l2_entry->value.lag_id == OF_GROUP_ANY) {
        AIM_LOG_VERBOSE("L2 destination discard");
        mark_drop(ctx);
    }

    process_debug(ctx, cfr, orig_vlan_vid);
    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    uint32_t dst_port_no;
    if (select_lag_port(dst_l2_entry->value.lag_id, ctx->hash, &dst_port_no) < 0) {
        return;
    }
    AIM_LOG_VERBOSE("selected LAG port %u", dst_port_no);

    process_egress(ctx,
                   dst_port_no,
                   vlan_vid,
                   port_entry->value.lag_id,
                   0, /* l3_interface_class_id */
                   false); /* l3 */
}

static void
process_l3(struct ctx *ctx,
           struct ind_ovs_cfr *cfr,
           uint32_t ingress_lag_id,
           uint16_t orig_vlan_vid,
           uint8_t ttl)
{
    struct next_hop *next_hop = NULL;
    bool cpu = false;
    bool drop = false;

    if (ttl <= 1) {
        AIM_LOG_VERBOSE("sending TTL expired packet to agent");
        mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_TTL_EXPIRED);
        mark_drop(ctx);
    } else {
        lookup_l3_route(cfr->vrf, cfr->nw_dst, &next_hop, &cpu);
    }

    process_debug(ctx, cfr, orig_vlan_vid);

    lookup_ingress_acl(ctx, cfr, &next_hop, &cpu, &drop);

    bool hit = next_hop != NULL;
    bool valid_next_hop = next_hop != NULL && next_hop->group_id != OF_GROUP_ANY;

    if (ttl <= 1) {
        if (cpu) {
            AIM_LOG_VERBOSE("L3 copy to CPU");
            mark_pktin_agent(ctx, OFP_BSN_PKTIN_FLAG_L3_CPU);
        }
    } else if (cpu) {
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

    process_pktin(ctx);

    if (ctx->drop) {
        return;
    }

    AIM_ASSERT(valid_next_hop);

    if (group_to_table_id(next_hop->group_id) == GROUP_TABLE_ID_ECMP) {
        if (select_ecmp_route(next_hop->group_id, ctx->hash, &next_hop) < 0) {
            return;
        }
    }

    AIM_ASSERT(group_to_table_id(next_hop->group_id) == GROUP_TABLE_ID_LAG);

    AIM_LOG_VERBOSE("next-hop: eth_src=%{mac} eth_dst=%{mac} vlan=%u lag_id=%u",
                    next_hop->new_eth_src.addr, next_hop->new_eth_dst.addr,
                    next_hop->new_vlan_vid, next_hop->group_id);

    uint32_t out_port;
    if (select_lag_port(next_hop->group_id, ctx->hash, &out_port) < 0) {
        return;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", out_port);

    set_eth_src(ctx->result, next_hop->new_eth_src);
    set_eth_dst(ctx->result, next_hop->new_eth_dst);
    dec_nw_ttl(ctx->result);

    process_egress(ctx,
                   out_port,
                   next_hop->new_vlan_vid,
                   ingress_lag_id,
                   cfr->l3_interface_class_id,
                   true); /* l3 */
}

static void
process_debug(struct ctx *ctx,
              struct ind_ovs_cfr *cfr,
              uint16_t orig_vlan_vid)
{
    uint32_t span_id;
    bool cpu, drop;

    lookup_debug(ctx, cfr, &span_id, &cpu, &drop);

    if (span_id != OF_GROUP_ANY) {
        if (orig_vlan_vid != 0) {
            set_vlan_vid(ctx->result, orig_vlan_vid);
        } else {
            pop_vlan(ctx->result);
        }
        span(ctx, span_id);
        set_vlan_vid(ctx->result, VLAN_VID(ntohs(cfr->dl_vlan)));
    }

    if (cpu) {
        if (!(ctx->pktin_metadata & (OFP_BSN_PKTIN_FLAG_ARP|
                                     OFP_BSN_PKTIN_FLAG_DHCP|
                                     OFP_BSN_PKTIN_FLAG_STATION_MOVE))) {
            mark_pktin_controller(ctx, OFP_BSN_PKTIN_FLAG_DEBUG);
        }
    }

    if (drop) {
        mark_drop(ctx);
    }
}

static void
process_egress(struct ctx *ctx,
               uint32_t out_port,
               uint16_t vlan_vid, /* internal VLAN */
               uint32_t ingress_lag_id,
               uint32_t l3_interface_class_id,
               bool l3)
{
    struct vlan_entry *vlan_entry = pipeline_bvs_table_vlan_lookup(vlan_vid);
    if (!vlan_entry) {
        AIM_LOG_VERBOSE("Packet routed to unconfigured vlan %u", vlan_vid);
        return;
    }

    bool out_port_tagged;
    if (!check_vlan_membership(vlan_entry, out_port, &out_port_tagged)) {
        AIM_LOG_VERBOSE("output port %u not allowed on vlan %u", out_port, vlan_vid);
        return;
    }

    struct port_entry *dst_port_entry = pipeline_bvs_table_port_lookup(out_port);
    if (!dst_port_entry) {
        return;
    }

    if (!l3 && dst_port_entry->value.lag_id != OF_GROUP_ANY &&
            dst_port_entry->value.lag_id == ingress_lag_id) {
        AIM_LOG_VERBOSE("skipping ingress LAG %u", ingress_lag_id);
        return;
    }

    /* Egress VLAN translation */
    uint16_t tag = vlan_vid;
    if (!out_port_tagged) {
        pop_vlan(ctx->result);
        tag = 0;
    } else {
        struct egr_vlan_xlate_entry *egr_vlan_xlate_entry =
            pipeline_bvs_table_egr_vlan_xlate_lookup(out_port, vlan_vid);
        if (egr_vlan_xlate_entry) {
            tag = egr_vlan_xlate_entry->value.new_vlan_vid;
        }
        set_vlan_vid(ctx->result, tag);
    }

    /* Egress ACL */
    if (l3) {
        struct egress_acl_key key = {
            .vlan_vid = tag,
            .egr_port_group_id = dst_port_entry->value.egr_port_group_id,
            .l3_interface_class_id = l3_interface_class_id,
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
        span(ctx, egress_mirror_entry->value.span_id);
    }

    output(ctx->result, out_port);
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

    if (in_port == OF_PORT_DEST_LOCAL) {
        if (tagged) {
            *tagged = true;
        }
        return true;
    }

    return false;
}

static void
flood_vlan(struct ctx *ctx, uint16_t vlan_vid, uint32_t lag_id)
{
    struct flood_key key = { .lag_id = lag_id };
    struct flood_entry *entry = pipeline_bvs_table_flood_lookup(&key);
    if (entry == NULL) {
        AIM_LOG_VERBOSE("missing VLAN entry for vlan %u", vlan_vid);
        return;
    }

    int i;
    for (i = 0; i < entry->value.num_lag_ids; i++) {
        uint32_t group_id = entry->value.lag_ids[i];
        uint32_t port_no;

        if (select_lag_port(group_id, ctx->hash, &port_no) < 0) {
            AIM_LOG_VERBOSE("LAG %u is empty", group_id);
            continue;
        }
        AIM_LOG_VERBOSE("selected LAG %u port %u", group_id, port_no);

        process_egress(ctx,
                       port_no,
                       vlan_vid,
                       lag_id,
                       0, /* l3_interface_class_id */
                       false); /* l3 */
    }
}

static void
span(struct ctx *ctx, uint32_t span_id)
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
    if (select_lag_port(dst_group_id, ctx->hash, &dst_port_no) < 0) {
        return;
    }
    AIM_LOG_VERBOSE("Selected LAG port %u", dst_port_no);

    output(ctx->result, dst_port_no);
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
    struct next_hop **next_hop)
{
    indigo_error_t rv;

    /*
     * HACK
     *
     * Eventually we will manage the memory allocated for ECMP groups
     * and we'll be able to just return a pointer to an already
     * parsed next_hop. The group infrastructure doesn't exist yet,
     * so fake it by returning a pointer to thread-local memory.
     */
    static __thread struct next_hop static_next_hop;

    struct xbuf *actions;
    rv = ind_ovs_group_select(group_id, hash, &actions);
    if (rv < 0) {
        AIM_LOG_WARN("error selecting ECMP group %u bucket: %s", group_id, indigo_strerror(rv));
        return rv;
    }

    memset(&static_next_hop, 0, sizeof(static_next_hop));
    static_next_hop.group_id = OF_GROUP_ANY;

    struct nlattr *attr;
    XBUF_FOREACH2(actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            static_next_hop.group_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(static_next_hop.new_eth_src.addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(static_next_hop.new_eth_dst.addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            static_next_hop.new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        }
    }

    *next_hop = &static_next_hop;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l3_route(uint32_t vrf, uint32_t ipv4_dst,
                struct next_hop **next_hop, bool *cpu)
{
    AIM_LOG_VERBOSE("looking up route for VRF=%u ip=%{ipv4a}", vrf, htonl(ipv4_dst));

    *next_hop = NULL;
    *cpu = false;

    {
        struct l3_host_route_key key = { .vrf=vrf, .ipv4 = htonl(ipv4_dst) };
        struct l3_host_route_entry *entry = pipeline_bvs_table_l3_host_route_lookup(&key);
        if (entry != NULL) {
            *next_hop = &entry->value.next_hop;
            *cpu = entry->value.cpu;
        }
    }

    if (!*next_hop) {
        struct l3_cidr_route_key key = { .vrf=vrf, .ipv4 = htonl(ipv4_dst) };
        struct l3_cidr_route_entry *entry = pipeline_bvs_table_l3_cidr_route_lookup(&key);
        if (entry != NULL) {
            *next_hop = &entry->value.next_hop;
            *cpu = entry->value.cpu;
        }
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static void
lookup_debug(struct ctx *ctx, struct ind_ovs_cfr *cfr, uint32_t *span_id, bool *cpu, bool *drop)
{
    struct debug_key key = {
        .in_port = cfr->in_port,
        .eth_type = ntohs(cfr->dl_type),
        .vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan)),
        .ipv4_src = ntohl(cfr->nw_src),
        .ipv4_dst = ntohl(cfr->nw_dst),
        .ip_proto = cfr->nw_proto,
        .ip_tos = cfr->nw_tos,
        .tp_src = ntohs(cfr->tp_src),
        .tp_dst = ntohs(cfr->tp_dst),
        .pad = 0,
    };

    memcpy(&key.eth_src, cfr->dl_src, OF_MAC_ADDR_BYTES);
    memcpy(&key.eth_dst, cfr->dl_dst, OF_MAC_ADDR_BYTES);

    struct debug_entry *entry = pipeline_bvs_table_debug_lookup(&key);
    if (entry == NULL) {
        *span_id = OF_GROUP_ANY;
        *drop = false;
        *cpu = false;
        return;
    }

    *span_id = entry->value.span_id;
    *drop = entry->value.drop;
    *cpu = entry->value.cpu;

    apply_stats(ctx->result, &entry->stats);
}

static struct vlan_acl_key
make_vlan_acl_key(struct ind_ovs_cfr *cfr)
{
    struct vlan_acl_key key = {
        .vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan)),
        .pad = 0,
    };
    memcpy(&key.eth_src, cfr->dl_src, OF_MAC_ADDR_BYTES);
    memcpy(&key.eth_dst, cfr->dl_dst, OF_MAC_ADDR_BYTES);

    return key;
}

static void
lookup_ingress_acl(struct ctx *ctx, struct ind_ovs_cfr *cfr,
                   struct next_hop **next_hop, bool *cpu, bool *drop)
{
    /* Assumes return value memory is initialized */

    struct ingress_acl_key key = {
        .in_port = cfr->in_port,
        .vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan)),
        .ip_proto = cfr->nw_proto,
        .pad = 0,
        .vrf = cfr->vrf,
        .l3_interface_class_id = cfr->l3_interface_class_id,
        .l3_src_class_id = cfr->l3_src_class_id,
        .ipv4_src = ntohl(cfr->nw_src),
        .ipv4_dst = ntohl(cfr->nw_dst),
        .tp_src = ntohs(cfr->tp_src),
        .tp_dst = ntohs(cfr->tp_dst),
    };

    struct ingress_acl_entry *entry = pipeline_bvs_table_ingress_acl_lookup(&key);
    if (entry == NULL) {
        return;
    }

    if (entry->value.drop) {
        *drop = true;
    }

    if (entry->value.cpu) {
        *cpu = true;
    }

    if (entry->value.next_hop.group_id != OF_GROUP_ANY) {
        *next_hop = &entry->value.next_hop;
    }

    apply_stats(ctx->result, &entry->stats);
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
        pktin(ctx->result, reason, ctx->pktin_metadata);
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
