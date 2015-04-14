/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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

#include "table_ifp.h"
#include <indigo/of_state_manager.h>
#include <ivs/ivs.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <packet_trace/packet_trace.h>
#include "pipeline_bigtap_int.h"

#define AIM_LOG_MODULE_NAME pipeline_bigtap
#include <AIM/aim_log.h>

static struct tcam *ifp_tcam;
static const of_match_fields_t maximum_mask = {
    .in_port = 0xffffffff,
    .eth_src = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .eth_type = 0xffff,
    .vlan_vid = 0xffff,
    .vlan_pcp = 0xff,
    .ipv4_src = 0xffffffff,
    .ipv4_dst = 0xffffffff,
    .ipv6_src = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .ipv6_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .ip_proto = 0xff,
    .ip_dscp = 0xff,
    .ip_ecn = 0xff,
    .tcp_src = 0xffff,
    .tcp_dst = 0xffff,
    .udp_src = 0xffff,
    .udp_dst = 0xffff,
    .icmpv4_type = 0xff,
    .icmpv4_code = 0xff,
    .icmpv6_type = 0xff,
    .icmpv6_code = 0xff,
    .bsn_tcp_flags = 0xffff,
};
static const of_match_fields_t minimum_mask = {
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct ifp_key *key,
          struct ifp_key *mask, uint16_t *priority)
{
    memset(key, 0, sizeof(*key));
    memset(mask, 0, sizeof(*mask));

    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        AIM_LOG_WARN("Failed to extract match");
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bigtap_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        AIM_LOG_WARN("Maximum mask exceeded");
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (match.masks.ip_proto) {
        if (match.masks.ip_proto != 0xff) {
            AIM_LOG_WARN("Invalid ip_proto mask");
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_TCP) {
        if (match.masks.tcp_src || match.masks.tcp_dst) {
            AIM_LOG_WARN("Invalid tcp port mask");
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_UDP) {
        if (match.masks.udp_src || match.masks.udp_dst) {
            AIM_LOG_WARN("Invalid udp port mask");
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.masks.in_port && match.masks.in_port != 0xffffffff) {
        AIM_LOG_WARN("Invalid in_port mask");
        return INDIGO_ERROR_BAD_MATCH;
    }

    of_flow_add_priority_get(obj, priority);

    key->in_port = match.fields.in_port;
    mask->in_port = match.masks.in_port;

    memcpy(key->eth_dst, &match.fields.eth_dst, sizeof(key->eth_dst));
    memcpy(mask->eth_dst, &match.fields.eth_dst, sizeof(mask->eth_dst));

    memcpy(key->eth_src, &match.fields.eth_src, sizeof(key->eth_src));
    memcpy(mask->eth_src, &match.fields.eth_src, sizeof(mask->eth_src));

    key->eth_type = match.fields.eth_type;
    mask->eth_type = match.fields.eth_type;

    key->vlan = VLAN_TCI_WITH_CFI(match.fields.vlan_vid, match.fields.vlan_pcp);
    mask->vlan = VLAN_TCI_WITH_CFI(match.masks.vlan_vid, match.masks.vlan_pcp);

    key->ip_proto = match.fields.ip_proto;
    mask->ip_proto = match.masks.ip_proto;

    key->ipv4_src = match.fields.ipv4_src;
    mask->ipv4_src = match.masks.ipv4_src;

    key->ipv4_dst = match.fields.ipv4_dst;
    mask->ipv4_dst = match.masks.ipv4_dst;

    memcpy(key->ipv6_src, &match.fields.ipv6_src, sizeof(key->ipv6_src));
    memcpy(key->ipv6_dst, &match.fields.ipv6_dst, sizeof(key->ipv6_dst));

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
parse_value(of_flow_add_t *obj, struct ifp_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    AIM_BITMAP_INIT(&value->out_port_bitmap, MAX_PORTS);
    value->new_vlan_vid = VLAN_INVALID;

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
                case OF_ACTION_OUTPUT: {
                    of_port_no_t port_no;
                    of_action_output_port_get(&act, &port_no);
                    if (port_no < MAX_PORTS) {
                        AIM_BITMAP_SET(&value->out_port_bitmap, port_no);
                    } else {
                        AIM_LOG_ERROR("Unexpected output port %u in ifp table", port_no);
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_SET_FIELD: {
                    of_object_t oxm;
                    of_action_set_field_field_bind(&act, &oxm);
                    switch (oxm.object_id) {
                    case OF_OXM_VLAN_VID:
                        of_oxm_vlan_vid_value_get(&oxm, &value->new_vlan_vid);
                        value->new_vlan_vid &= ~VLAN_CFI_BIT;
                        break;
                    default:
                        AIM_LOG_ERROR("Unexpected set-field OXM %s in port table", of_object_id_str[oxm.object_id]);
                        goto error;
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in ifp table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in ifp table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bigtap_table_ifp_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct ifp_entry *entry = aim_zmalloc(sizeof(*entry));
    struct ifp_key key;
    struct ifp_key mask;
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

    AIM_LOG_VERBOSE("Create ifp entry prio=%u in_port=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} eth_type=%#x/%#x vlan=%#x/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} ip_proto=%u/%#x ip_tos=%#x/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> out_ports=%{aim_bitmap}",
                    priority, key.in_port, mask.in_port, &key.eth_src, &mask.eth_src, &key.eth_dst, &mask.eth_dst, key.eth_type, mask.eth_type, key.vlan, mask.vlan, key.ipv4_src, mask.ipv4_src, key.ipv4_dst, mask.ipv4_dst, key.ip_proto, mask.ip_proto, key.ip_tos, mask.ip_tos, key.tp_src, mask.tp_src, key.tp_dst, mask.tp_dst, key.tcp_flags, mask.tcp_flags,
                    &entry->value.out_port_bitmap);

    stats_alloc(&entry->stats_handle);

    tcam_insert(ifp_tcam, &entry->tcam_entry, &key, &mask, priority);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_ifp_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct ifp_entry *entry = entry_priv;
    struct ifp_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;
    entry->value.out_port_bitmap.hdr.words = entry->value.out_port_bitmap.words;

    const struct ifp_key *entry_key = entry->tcam_entry.key;
    const struct ifp_key *entry_mask = entry->tcam_entry.mask;
    AIM_LOG_VERBOSE("Modify ifp entry prio=%u in_port=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} eth_type=%#x/%#x vlan=%#x/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} ip_proto=%u/%#x ip_tos=%#x/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> out_ports=%{aim_bitmap}",
                    entry->tcam_entry.priority, entry_key->in_port, entry_mask->in_port, &entry_key->eth_src, &entry_mask->eth_src, &entry_key->eth_dst, &entry_mask->eth_dst, entry_key->eth_type, entry_mask->eth_type, entry_key->vlan, entry_mask->vlan, entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst, entry_key->ip_proto, entry_mask->ip_proto, entry_key->ip_tos, entry_mask->ip_tos, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags,
                    &entry->value.out_port_bitmap);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_ifp_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ifp_entry *entry = entry_priv;

    tcam_remove(ifp_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_ifp_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ifp_entry *entry = entry_priv;
    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_ifp_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bigtap_table_ifp_entry_create,
    .entry_modify = pipeline_bigtap_table_ifp_entry_modify,
    .entry_delete = pipeline_bigtap_table_ifp_entry_delete,
    .entry_stats_get = pipeline_bigtap_table_ifp_entry_stats_get,
    .entry_hit_status_get = pipeline_bigtap_table_ifp_entry_hit_status_get,
};

void
pipeline_bigtap_table_ifp_register(void)
{
    ifp_tcam = tcam_create(sizeof(struct ifp_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_IFP, "ifp", &table_ops, NULL);
}

void
pipeline_bigtap_table_ifp_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_IFP);
    tcam_destroy(ifp_tcam);
}

struct ifp_entry *
pipeline_bigtap_table_ifp_lookup(const struct ifp_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(ifp_tcam, key);
    if (tcam_entry) {
        struct ifp_entry *entry = container_of(tcam_entry, tcam_entry, struct ifp_entry);
        const struct ifp_key *entry_key = tcam_entry->key;
        const struct ifp_key *entry_mask = tcam_entry->mask;
        packet_trace("Hit ifp entry prio=%u in_port=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} eth_type=%#x/%#x vlan=%#x/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} ip_proto=%u/%#x ip_tos=%#x/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                     " -> out_ports=%{aim_bitmap}",
                     tcam_entry->priority, entry_key->in_port, entry_mask->in_port, &entry_key->eth_src, &entry_mask->eth_src, &entry_key->eth_dst, &entry_mask->eth_dst, entry_key->eth_type, entry_mask->eth_type, entry_key->vlan, entry_mask->vlan, entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst, entry_key->ip_proto, entry_mask->ip_proto, entry_key->ip_tos, entry_mask->ip_tos, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags,
                     &entry->value.out_port_bitmap);
        return entry;
    } else {
        packet_trace("Miss ifp entry in_port=%u eth_src=%{mac} eth_dst=%{mac} eth_type=%#x vlan=%#x ipv4_src=%{ipv4a} ipv4_dst=%{ipv4a} ip_proto=%u ip_tos=%#x tp_src=%u tp_dst=%u tcp_flags=%#x",
                     key->in_port, &key->eth_src, &key->eth_dst, key->eth_type, key->vlan, key->ipv4_src, key->ipv4_dst, key->ip_proto, key->ip_tos, key->tp_src, key->tp_dst, key->tcp_flags);
        return NULL;
    }
}
