/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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
#include <linux/if_ether.h>

static void cleanup_value(struct debug_value *value);

static struct tcam *debug_tcam;
static const of_match_fields_t maximum_mask = {
    .in_port = 0xffffffff,
    .bsn_ingress_port_group_id = 0xffffffff,
    .eth_src = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .eth_type = 0xffff,
    .vlan_vid = 0xffff,
    .bsn_vrf = 0xffffffff,
    .ipv4_src = 0xffffffff,
    .ipv4_dst = 0xffffffff,
    .ip_proto = 0xff,
    .ip_dscp = 0xff,
    .ip_ecn = 0xff,
    .tcp_src = 0xffff,
    .tcp_dst = 0xffff,
    .udp_src = 0xffff,
    .udp_dst = 0xffff,
    .bsn_tcp_flags = 0xffff,
};
static const of_match_fields_t minimum_mask = {
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct debug_key *key,
          struct debug_key *mask, uint16_t *priority)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (match.masks.ip_proto) {
        if (match.masks.ip_proto != 0xff) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_TCP) {
        if (match.masks.tcp_src || match.masks.tcp_dst) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_UDP) {
        if (match.masks.udp_src || match.masks.udp_dst) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.masks.in_port && match.masks.in_port != 0xffffffff) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    of_flow_add_priority_get(obj, priority);

    key->in_port = match.fields.in_port;
    mask->in_port = match.masks.in_port;

    key->ingress_port_group_id = match.fields.bsn_ingress_port_group_id;
    mask->ingress_port_group_id = match.masks.bsn_ingress_port_group_id;

    key->eth_src = match.fields.eth_src;
    mask->eth_src = match.masks.eth_src;

    key->eth_dst = match.fields.eth_dst;
    mask->eth_dst = match.masks.eth_dst;

    key->eth_type = match.fields.eth_type;
    mask->eth_type = match.fields.eth_type;

    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    mask->vlan_vid = match.masks.vlan_vid;

    key->vrf = match.fields.bsn_vrf;
    mask->vrf = match.masks.bsn_vrf;

    key->ip_proto = match.fields.ip_proto;
    mask->ip_proto = match.masks.ip_proto;

    key->ipv4_src = match.fields.ipv4_src;
    mask->ipv4_src = match.masks.ipv4_src;

    key->ipv4_dst = match.fields.ipv4_dst;
    mask->ipv4_dst = match.masks.ipv4_dst;

    key->ip_tos = ((match.fields.ip_dscp << 2) & IP_DSCP_MASK) | (match.fields.ip_ecn & IP_ECN_MASK);
    mask->ip_tos = ((match.masks.ip_dscp << 2) & IP_DSCP_MASK) | (match.masks.ip_ecn & IP_ECN_MASK);

    key->tcp_flags = mask->tcp_flags = 0;
    if (key->ip_proto == IPPROTO_TCP) {
        key->tp_src = match.fields.tcp_src;
        mask->tp_src = match.masks.tcp_src;
        key->tp_dst = match.fields.tcp_dst;
        mask->tp_dst = match.masks.tcp_dst;
        key->tcp_flags = match.fields.bsn_tcp_flags;
        mask->tcp_flags = match.masks.bsn_tcp_flags;
    } else if (key->ip_proto == IPPROTO_UDP) {
        key->tp_src = match.fields.udp_src;
        mask->tp_src = match.masks.udp_src;
        key->tp_dst = match.fields.udp_dst;
        mask->tp_dst = match.masks.udp_dst;
    } else {
        key->tp_src = mask->tp_src = 0;
        key->tp_dst = mask->tp_dst = 0;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct debug_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    value->span = NULL;
    value->lag = NULL;
    value->drop = false;
    value->cpu = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.object_id) {
        case OF_INSTRUCTION_APPLY_ACTIONS: {
            of_list_action_t actions;
            of_instruction_apply_actions_actions_bind(&inst, &actions);
            of_object_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.object_id) {
                case OF_ACTION_GROUP: {
                    if (value->span == NULL) {
                        uint32_t span_id;
                        of_action_group_group_id_get(&act, &span_id);
                        value->span = pipeline_bvs_group_span_acquire(span_id);
                        if (value->span == NULL) {
                            AIM_LOG_ERROR("Nonexistent SPAN in debug table");
                            goto error;
                        }
                    } else {
                        AIM_LOG_ERROR("Duplicate SPAN action in debug table");
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_BSN_GENTABLE: {
                    of_object_t key;
                    uint32_t table_id;
                    of_action_bsn_gentable_table_id_get(&act, &table_id);
                    of_action_bsn_gentable_key_bind(&act, &key);
                    if (table_id == pipeline_bvs_table_span_id) {
                        if (value->span != NULL) {
                            AIM_LOG_ERROR("Duplicate SPAN action in debug table");
                            goto error;
                        }
                        value->span = pipeline_bvs_table_span_acquire(&key);
                        if (value->span == NULL) {
                            AIM_LOG_ERROR("Nonexistent SPAN in debug table");
                            goto error;
                        }
                    } else if (table_id == pipeline_bvs_table_lag_id) {
                        if (value->lag != NULL) {
                            AIM_LOG_ERROR("Duplicate LAG action in debug table");
                            goto error;
                        }
                        value->lag = pipeline_bvs_table_lag_acquire(&key);
                        if (value->lag == NULL) {
                            AIM_LOG_ERROR("Nonexistent LAG in debug table");
                            goto error;
                        }
                    } else {
                        AIM_LOG_ERROR("unsupported gentable reference in debug table");
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_OUTPUT: {
                    of_port_no_t port_no;
                    of_action_output_port_get(&act, &port_no);
                    switch (port_no) {
                        case OF_PORT_DEST_CONTROLLER: {
                            value->cpu = true;
                            break;
                        default:
                            AIM_LOG_ERROR("Unexpected output port %u in debug_table", port_no);
                            goto error;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in debug table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        case OF_INSTRUCTION_BSN_DENY:
            value->drop = true;
            break;
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in debug table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct debug_value *value)
{
    if (value->span != NULL) {
        pipeline_bvs_table_span_release(value->span);
    }
}

static indigo_error_t
pipeline_bvs_table_debug_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct debug_entry *entry = aim_zmalloc(sizeof(*entry));
    struct debug_key key;
    struct debug_key mask;
    uint16_t priority;

    rv = parse_key(obj, &key, &mask, &priority);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    rv = parse_value(obj, &entry->value);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create debug entry prio=%u in_port=%u/%#x ingress_port_group_id=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} eth_type=%#x/%#x vlan_vid=%u/%#x vrf=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} ip_proto=%u/%#x ip_tos=%#x/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> span=%s lag=%s cpu=%d drop=%d",
                    priority, key.in_port, mask.in_port, key.ingress_port_group_id, mask.ingress_port_group_id, &key.eth_src, &mask.eth_src, &key.eth_dst, &mask.eth_dst, key.eth_type, mask.eth_type, key.vlan_vid, mask.vlan_vid, key.vrf, mask.vrf, key.ipv4_src, mask.ipv4_src, key.ipv4_dst, mask.ipv4_dst, key.ip_proto, mask.ip_proto, key.ip_tos, mask.ip_tos, key.tp_src, mask.tp_src, key.tp_dst, mask.tp_dst, key.tcp_flags, mask.tcp_flags,
                    span_name(entry->value.span), lag_name(entry->value.lag), entry->value.cpu, entry->value.drop);

    stats_alloc(&entry->stats_handle);

    tcam_insert(debug_tcam, &entry->tcam_entry, &key, &mask, priority);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_debug_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct debug_entry *entry = entry_priv;
    struct debug_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_debug_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct debug_entry *entry = entry_priv;

    tcam_remove(debug_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_debug_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct debug_entry *entry = entry_priv;
    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_debug_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_debug_entry_create,
    .entry_modify = pipeline_bvs_table_debug_entry_modify,
    .entry_delete = pipeline_bvs_table_debug_entry_delete,
    .entry_stats_get = pipeline_bvs_table_debug_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_debug_entry_hit_status_get,
};

void
pipeline_bvs_table_debug_register(void)
{
    debug_tcam = tcam_create(sizeof(struct debug_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_DEBUG, "debug", &table_ops, NULL);
}

void
pipeline_bvs_table_debug_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_DEBUG);
    tcam_destroy(debug_tcam);
}

struct debug_entry *
pipeline_bvs_table_debug_lookup(const struct debug_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(debug_tcam, key);
    if (tcam_entry) {
        struct debug_entry *entry = container_of(tcam_entry, tcam_entry, struct debug_entry);
        const struct debug_key *entry_key = tcam_entry->key;
        const struct debug_key *entry_mask = tcam_entry->mask;
        packet_trace("Hit debug entry prio=%u in_port=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} eth_type=%#x/%#x vlan_vid=%u/%#x vrf=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} ip_proto=%u/%#x ip_tos=%#x/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                     " -> span_id=%u cpu=%d drop=%d",
                     tcam_entry->priority, entry_key->in_port, entry_mask->in_port, &entry_key->eth_src, &entry_mask->eth_src, &entry_key->eth_dst, &entry_mask->eth_dst, entry_key->eth_type, entry_mask->eth_type, entry_key->vlan_vid, entry_mask->vlan_vid, entry_key->vrf, entry_mask->vrf, entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst, entry_key->ip_proto, entry_mask->ip_proto, entry_key->ip_tos, entry_mask->ip_tos, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags,
                     entry->value.span ? entry->value.span->id : OF_GROUP_ANY, entry->value.cpu, entry->value.drop);
        return entry;
    } else {
        packet_trace("Miss debug entry in_port=%u eth_src=%{mac} eth_dst=%{mac} eth_type=%#x vlan_vid=%u vrf=%u ipv4_src=%{ipv4a} ipv4_dst=%{ipv4a} ip_proto=%u ip_tos=%#x tp_src=%u tp_dst=%u tcp_flags=%#x",
                     key->in_port, &key->eth_src, &key->eth_dst, key->eth_type, key->vlan_vid, key->vrf, key->ipv4_src, key->ipv4_dst, key->ip_proto, key->ip_tos, key->tp_src, key->tp_dst, key->tcp_flags);
        return NULL;
    }
}
