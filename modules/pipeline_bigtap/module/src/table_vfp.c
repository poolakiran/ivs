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

#include "table_vfp.h"
#include <indigo/of_state_manager.h>
#include <ivs/ivs.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <packet_trace/packet_trace.h>
#include "pipeline_bigtap_int.h"

#define AIM_LOG_MODULE_NAME pipeline_bigtap
#include <AIM/aim_log.h>

static struct tcam *vfp_tcam;
static const of_match_fields_t maximum_mask = {
    .in_port = 0xffffffff,
    .eth_type = 0xffff,
    .ip_proto = 0xff,
    .udp_src = 0xffff,
    .udp_dst = 0xffff,
    .bsn_tcp_flags = 0xffff,
};
static const of_match_fields_t minimum_mask = {
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct vfp_key *key,
          struct vfp_key *mask, uint16_t *priority)
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

    key->eth_type = match.fields.eth_type;
    mask->eth_type = match.fields.eth_type;

    key->ip_proto = match.fields.ip_proto;
    mask->ip_proto = match.masks.ip_proto;

    if (key->ip_proto == IPPROTO_TCP) {
        key->tcp_flags = match.fields.bsn_tcp_flags;
        mask->tcp_flags = match.masks.bsn_tcp_flags;
    } else if (key->ip_proto == IPPROTO_UDP) {
        key->tp_src = match.fields.udp_src;
        mask->tp_src = match.masks.udp_src;
        key->tp_dst = match.fields.udp_dst;
        mask->tp_dst = match.masks.udp_dst;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct vfp_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

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
                case OF_ACTION_OUTPUT: {
                    of_port_no_t port_no;
                    of_action_output_port_get(&act, &port_no);
                    if (port_no == OF_PORT_DEST_CONTROLLER) {
                        value->cpu = true;
                    } else {
                        AIM_LOG_ERROR("Unexpected output port %u in vfp table", port_no);
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_SET_QUEUE:
                    /* ignore */
                    break;
                default:
                    AIM_LOG_ERROR("Unexpected action %s in vfp table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in vfp table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bigtap_table_vfp_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct vfp_entry *entry = aim_zmalloc(sizeof(*entry));
    struct vfp_key key;
    struct vfp_key mask;
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

    AIM_LOG_VERBOSE("Create vfp entry prio=%u in_port=%u/%#x eth_type=%#x/%#x ip_proto=%u/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> cpu=%d",
                    priority, key.in_port, mask.in_port, key.eth_type, mask.eth_type, key.ip_proto, mask.ip_proto, key.tp_src, mask.tp_src, key.tp_dst, mask.tp_dst, key.tcp_flags, mask.tcp_flags,
                    &entry->value.cpu);

    stats_alloc(&entry->stats_handle);

    tcam_insert(vfp_tcam, &entry->tcam_entry, &key, &mask, priority);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_vfp_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct vfp_entry *entry = entry_priv;
    struct vfp_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;

    const struct vfp_key *entry_key = entry->tcam_entry.key;
    const struct vfp_key *entry_mask = entry->tcam_entry.mask;
    AIM_LOG_VERBOSE("Modify vfp entry prio=%u in_port=%u/%#x eth_type=%#x/%#x ip_proto=%u/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> cpu=%d",
                    entry->tcam_entry.priority, entry_key->in_port, entry_mask->in_port, entry_key->eth_type, entry_mask->eth_type, entry_key->ip_proto, entry_mask->ip_proto, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags,
                    &entry->value.cpu);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_vfp_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vfp_entry *entry = entry_priv;

    tcam_remove(vfp_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_vfp_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vfp_entry *entry = entry_priv;
    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bigtap_table_vfp_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bigtap_table_vfp_entry_create,
    .entry_modify = pipeline_bigtap_table_vfp_entry_modify,
    .entry_delete = pipeline_bigtap_table_vfp_entry_delete,
    .entry_stats_get = pipeline_bigtap_table_vfp_entry_stats_get,
    .entry_hit_status_get = pipeline_bigtap_table_vfp_entry_hit_status_get,
};

void
pipeline_bigtap_table_vfp_register(void)
{
    vfp_tcam = tcam_create(sizeof(struct vfp_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_VFP, "vfp", &table_ops, NULL);
}

void
pipeline_bigtap_table_vfp_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_VFP);
    tcam_destroy(vfp_tcam);
}

struct vfp_entry *
pipeline_bigtap_table_vfp_lookup(const struct vfp_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(vfp_tcam, key);
    if (tcam_entry) {
        struct vfp_entry *entry = container_of(tcam_entry, tcam_entry, struct vfp_entry);
        const struct vfp_key *entry_key = tcam_entry->key;
        const struct vfp_key *entry_mask = tcam_entry->mask;
        packet_trace("Hit vfp entry prio=%u in_port=%u/%#x eth_type=%#x/%#x ip_proto=%u/%#x tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x"
                    " -> cpu=%d",
                    tcam_entry->priority, entry_key->in_port, entry_mask->in_port, entry_key->eth_type, entry_mask->eth_type, entry_key->ip_proto, entry_mask->ip_proto, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags,
                    &entry->value.cpu);
        return entry;
    } else {
        packet_trace("Miss vfp entry in_port=%u eth_type=%#x ip_proto=%u tp_src=%u tp_dst=%u tcp_flags=%#x",
                    key->in_port, key->eth_type, key->ip_proto, key->tp_src, key->tp_dst, key->tcp_flags);
        return NULL;
    }
}
