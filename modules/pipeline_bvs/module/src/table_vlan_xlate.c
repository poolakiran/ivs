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

#define TEMPLATE_NAME vlan_xlate_hashtable
#define TEMPLATE_OBJ_TYPE struct vlan_xlate_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *vlan_xlate_hashtable;
static const of_match_fields_t required_mask = {
    .bsn_lag_id = 0xffffffff,
    .vlan_vid = 0xffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct vlan_xlate_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_COMPAT;
    }
    key->lag_id = match.fields.bsn_lag_id;
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct vlan_xlate_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;
    bool seen_new_vlan_vid = false;

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
                case OF_ACTION_SET_FIELD: {
                    of_oxm_t oxm;
                    of_action_set_field_field_bind(&act.set_field, &oxm.header);
                    switch (oxm.header.object_id) {
                    case OF_OXM_VLAN_VID:
                        of_oxm_vlan_vid_value_get(&oxm.vlan_vid, &value->new_vlan_vid);
                        seen_new_vlan_vid = true;
                        break;
                    default:
                        AIM_LOG_WARN("Unexpected set-field OXM %s in vlan_xlate table", of_object_id_str[oxm.header.object_id]);
                        break;
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in vlan_xlate table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        default:
            AIM_LOG_WARN("Unexpected instruction %s in vlan_xlate table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    if (!seen_new_vlan_vid) {
        AIM_LOG_WARN("Missing required instruction in vlan_xlate table");
        return INDIGO_ERROR_COMPAT;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_xlate_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct vlan_xlate_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create vlan_xlate entry lag_id=%u, vlan=%u -> vlan %u",
                    entry->key.lag_id, &entry->key.vlan_vid,
                    entry->value.new_vlan_vid);

    ind_ovs_fwd_write_lock();
    vlan_xlate_hashtable_insert(vlan_xlate_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_xlate_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct vlan_xlate_entry *entry = entry_priv;
    struct vlan_xlate_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_xlate_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vlan_xlate_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(vlan_xlate_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_xlate_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static indigo_error_t
pipeline_bvs_table_vlan_xlate_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_vlan_xlate_entry_create,
    .entry_modify = pipeline_bvs_table_vlan_xlate_entry_modify,
    .entry_delete = pipeline_bvs_table_vlan_xlate_entry_delete,
    .entry_stats_get = pipeline_bvs_table_vlan_xlate_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_vlan_xlate_entry_hit_status_get,
};

void
pipeline_bvs_table_vlan_xlate_register(void)
{
    vlan_xlate_hashtable = bighash_table_create(16 * 1024);
    indigo_core_table_register(TABLE_ID_VLAN_XLATE, "vlan_xlate", &table_ops, NULL);
}

void
pipeline_bvs_table_vlan_xlate_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_VLAN_XLATE);
    bighash_table_destroy(vlan_xlate_hashtable, NULL);
}

struct vlan_xlate_entry *
pipeline_bvs_table_vlan_xlate_lookup(const struct vlan_xlate_key *key)
{
    struct vlan_xlate_entry *entry = vlan_xlate_hashtable_first(vlan_xlate_hashtable, key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit vlan_xlate entry lag_id=%u, vlan=%u -> vlan %u",
                        entry->key.lag_id, entry->key.vlan_vid,
                        entry->value.new_vlan_vid);
    } else {
        AIM_LOG_VERBOSE("Miss vlan_xlate entry lag_id=%u, vlan=%u",
                        key->lag_id, key->vlan_vid);
    }
    return entry;
}