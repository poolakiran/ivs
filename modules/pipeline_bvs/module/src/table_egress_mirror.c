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

#define TEMPLATE_NAME egress_mirror_hashtable
#define TEMPLATE_OBJ_TYPE struct egress_mirror_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static void cleanup_value(struct egress_mirror_value *value);

static bighash_table_t *egress_mirror_hashtable;
static const of_match_fields_t required_mask = {
    .in_port = 0xffffffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct egress_mirror_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_COMPAT;
    }
    key->out_port = match.fields.in_port;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct egress_mirror_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;
    bool seen_span_id = false;

    value->span = NULL;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.header.object_id) {
        case OF_INSTRUCTION_APPLY_ACTIONS: {
            of_list_action_t actions;
            of_instruction_apply_actions_actions_bind(&inst.apply_actions, &actions);
            of_action_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.header.object_id) {
                case OF_ACTION_GROUP:
                    if (!seen_span_id) {
                        uint32_t span_id;
                        of_action_group_group_id_get(&act.group, &span_id);
                        value->span = pipeline_bvs_group_span_acquire(span_id);
                        if (value->span == NULL) {
                            AIM_LOG_ERROR("Nonexistent SPAN in egress_mirror table");
                            goto error;
                        }
                        seen_span_id = true;
                    } else {
                        AIM_LOG_ERROR("Duplicate SPAN action in egress_mirror table");
                        goto error;
                    }
                    break;
                default:
                    AIM_LOG_ERROR("Unexpected action %s in egress_mirror table", of_object_id_str[act.header.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in egress_mirror table", of_object_id_str[inst.header.object_id]);
            goto error;
        }
    }

    if (!seen_span_id) {
        AIM_LOG_WARN("Missing required instruction in egress_mirror table");
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct egress_mirror_value *value)
{
    if (value->span) {
        pipeline_bvs_group_span_release(value->span);
    }
}

static indigo_error_t
pipeline_bvs_table_egress_mirror_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct egress_mirror_entry *entry = aim_zmalloc(sizeof(*entry));

    rv = parse_key(obj, &entry->key);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    rv = parse_value(obj, &entry->value);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create egress_mirror entry out_port=%u -> span_id %u",
                    entry->key.out_port, entry->value.span->id);

    ind_ovs_fwd_write_lock();
    egress_mirror_hashtable_insert(egress_mirror_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_mirror_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct egress_mirror_entry *entry = entry_priv;
    struct egress_mirror_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&entry->value);
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_mirror_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct egress_mirror_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(egress_mirror_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_mirror_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_mirror_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_egress_mirror_entry_create,
    .entry_modify = pipeline_bvs_table_egress_mirror_entry_modify,
    .entry_delete = pipeline_bvs_table_egress_mirror_entry_delete,
    .entry_stats_get = pipeline_bvs_table_egress_mirror_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_egress_mirror_entry_hit_status_get,
};

void
pipeline_bvs_table_egress_mirror_register(void)
{
    egress_mirror_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_EGRESS_MIRROR, "egress_mirror", &table_ops, NULL);
}

void
pipeline_bvs_table_egress_mirror_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_EGRESS_MIRROR);
    bighash_table_destroy(egress_mirror_hashtable, NULL);
}

struct egress_mirror_entry *
pipeline_bvs_table_egress_mirror_lookup(uint32_t port_no)
{
    struct egress_mirror_key key = { .out_port = port_no };
    struct egress_mirror_entry *entry = egress_mirror_hashtable_first(egress_mirror_hashtable, &key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit egress_mirror entry out_port=%u -> span_id %u",
                        entry->key.out_port, entry->value.span->id);
    } else {
        AIM_LOG_VERBOSE("Miss egress_mirror entry out_port=%u", key.out_port);
    }
    return entry;
}
