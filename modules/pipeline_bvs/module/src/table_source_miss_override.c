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

#define TEMPLATE_NAME source_miss_override_hashtable
#define TEMPLATE_OBJ_TYPE struct source_miss_override_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *source_miss_override_hashtable;
static const of_match_fields_t required_mask = {
    .vlan_vid = 0xffff,
    .in_port = 0xffffffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct source_miss_override_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    key->in_port = match.fields.in_port;
    key->pad = 0;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct source_miss_override_value *value)
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
                    of_port_no_t port;
                    of_action_output_port_get(&act, &port);
                    if (port != OF_PORT_DEST_CONTROLLER) {
                        AIM_LOG_ERROR("Unexpected output port %u in source_miss_override table", port);
                        goto error;
                    }
                    value->cpu = true;
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in source_miss_override table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in source_miss_override table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    if (!value->cpu) {
        AIM_LOG_ERROR("Missing required cpu action in source_miss_override table");
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bvs_table_source_miss_override_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct source_miss_override_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create source_miss_override entry vlan=%u port=%u -> cpu %u",
                    entry->key.vlan_vid, entry->key.in_port, entry->value.cpu);

    ind_ovs_fwd_write_lock();
    source_miss_override_hashtable_insert(source_miss_override_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_source_miss_override_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct source_miss_override_entry *entry = entry_priv;
    struct source_miss_override_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_source_miss_override_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct source_miss_override_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(source_miss_override_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_source_miss_override_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_source_miss_override_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_source_miss_override_entry_create,
    .entry_modify = pipeline_bvs_table_source_miss_override_entry_modify,
    .entry_delete = pipeline_bvs_table_source_miss_override_entry_delete,
    .entry_stats_get = pipeline_bvs_table_source_miss_override_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_source_miss_override_entry_hit_status_get,
};

void
pipeline_bvs_table_source_miss_override_register(void)
{
    source_miss_override_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_SOURCE_MISS_OVERRIDE, "source_miss_override", &table_ops, NULL);
}

void
pipeline_bvs_table_source_miss_override_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_SOURCE_MISS_OVERRIDE);
    bighash_table_destroy(source_miss_override_hashtable, NULL);
}

struct source_miss_override_entry *
pipeline_bvs_table_source_miss_override_lookup(uint16_t vlan_vid, uint32_t in_port)
{
    struct source_miss_override_key key = {
        .vlan_vid = vlan_vid & ~VLAN_CFI_BIT,
        .in_port = in_port,
        .pad = 0,
    };
    struct source_miss_override_entry *entry = source_miss_override_hashtable_first(source_miss_override_hashtable, &key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit source_miss_override entry vlan=%u port=%u -> cpu=%u",
                        entry->key.vlan_vid, entry->key.in_port, entry->value.cpu);
    } else {
        AIM_LOG_VERBOSE("Miss source_miss_override entry vlan=%u port=%u", key.vlan_vid, key.in_port);
    }
    return entry;
}
