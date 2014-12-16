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

#define TEMPLATE_NAME ingress_mirror_hashtable
#define TEMPLATE_OBJ_TYPE struct ingress_mirror_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static void cleanup_value(struct ingress_mirror_value *value);

static bighash_table_t *ingress_mirror_hashtable;
static const of_match_fields_t required_mask = {
    .in_port = 0xffffffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct ingress_mirror_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    key->in_port = match.fields.in_port;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct ingress_mirror_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;
    bool seen_span_id = false;

    value->span = NULL;

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
                case OF_ACTION_GROUP:
                    if (!seen_span_id) {
                        uint32_t span_id;
                        of_action_group_group_id_get(&act, &span_id);
                        value->span = pipeline_bvs_group_span_acquire(span_id);
                        if (value->span == NULL) {
                            AIM_LOG_ERROR("Nonexistent SPAN in ingress_mirror table");
                            goto error;
                        }
                        seen_span_id = true;
                    } else {
                        AIM_LOG_ERROR("Duplicate SPAN action in ingress_mirror table");
                        goto error;
                    }
                    break;
                default:
                    AIM_LOG_ERROR("Unexpected action %s in ingress_mirror table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in ingress_mirror table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    if (!seen_span_id) {
        AIM_LOG_ERROR("Missing required instruction in ingress_mirror table");
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct ingress_mirror_value *value)
{
    if (value->span) {
        pipeline_bvs_table_span_release(value->span);
    }
}

static indigo_error_t
pipeline_bvs_table_ingress_mirror_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct ingress_mirror_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create ingress_mirror entry in_port=%u -> span_id %u",
                    entry->key.in_port, entry->value.span->id);

    ingress_mirror_hashtable_insert(ingress_mirror_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_mirror_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct ingress_mirror_entry *entry = entry_priv;
    struct ingress_mirror_value value;

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
pipeline_bvs_table_ingress_mirror_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ingress_mirror_entry *entry = entry_priv;

    bighash_remove(ingress_mirror_hashtable, &entry->hash_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_mirror_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_mirror_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_ingress_mirror_entry_create,
    .entry_modify = pipeline_bvs_table_ingress_mirror_entry_modify,
    .entry_delete = pipeline_bvs_table_ingress_mirror_entry_delete,
    .entry_stats_get = pipeline_bvs_table_ingress_mirror_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_ingress_mirror_entry_hit_status_get,
};

void
pipeline_bvs_table_ingress_mirror_register(void)
{
    ingress_mirror_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_INGRESS_MIRROR, "ingress_mirror", &table_ops, NULL);
}

void
pipeline_bvs_table_ingress_mirror_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_INGRESS_MIRROR);
    bighash_table_destroy(ingress_mirror_hashtable, NULL);
}

struct ingress_mirror_entry *
pipeline_bvs_table_ingress_mirror_lookup(uint32_t port_no)
{
    struct ingress_mirror_key key = { .in_port = port_no };
    struct ingress_mirror_entry *entry = ingress_mirror_hashtable_first(ingress_mirror_hashtable, &key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit ingress_mirror entry in_port=%u -> span_id %u",
                        entry->key.in_port, entry->value.span->id);
    } else {
        AIM_LOG_VERBOSE("Miss ingress_mirror entry in_port=%u", key.in_port);
    }
    return entry;
}
