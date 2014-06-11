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

#define TEMPLATE_NAME vlan_hashtable
#define TEMPLATE_OBJ_TYPE struct vlan_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *vlan_hashtable;
static const of_match_fields_t required_mask = {
    .vlan_vid = 0xffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct vlan_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_COMPAT;
    }
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct vlan_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;
    bool tagged = true;
    int ports_size = 1;

    value->l3_interface_class_id = 0;
    value->vrf = 0;
    value->ports = aim_malloc(ports_size * sizeof(value->ports[0]));
    value->num_ports = 0;
    value->num_tagged_ports = 0;

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
                case OF_ACTION_OUTPUT:
                    if (value->num_ports >= ports_size) {
                        ports_size *= 2;
                        value->ports = aim_realloc(value->ports, ports_size * sizeof(value->ports[0]));
                    }
                    of_action_output_port_get(&act.output, &value->ports[value->num_ports++]);
                    if (tagged) {
                        value->num_tagged_ports++;
                    }
                    break;
                case OF_ACTION_POP_VLAN:
                    tagged = false;
                    break;
                case OF_ACTION_SET_FIELD: {
                    of_oxm_t oxm;
                    of_action_set_field_field_bind(&act.set_field, &oxm.header);
                    switch (oxm.header.object_id) {
                    case OF_OXM_BSN_L3_INTERFACE_CLASS_ID:
                        of_oxm_bsn_l3_interface_class_id_value_get(&oxm.bsn_l3_interface_class_id, &value->l3_interface_class_id);
                        break;
                    case OF_OXM_BSN_VRF:
                        of_oxm_bsn_vrf_value_get(&oxm.bsn_vrf, &value->vrf);
                        break;
                    default:
                        AIM_LOG_WARN("Unexpected set-field OXM %s in vlan table", of_object_id_str[oxm.header.object_id]);
                        break;
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in vlan table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        default:
            AIM_LOG_WARN("Unexpected instruction %s in vlan table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct vlan_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create vlan entry vlan=%u -> l3_interface_class_id=%#x vrf=%u",
                    entry->key.vlan_vid, entry->value.l3_interface_class_id, entry->value.vrf);

    ind_ovs_fwd_write_lock();
    vlan_hashtable_insert(vlan_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct vlan_entry *entry = entry_priv;
    struct vlan_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    aim_free(entry->value.ports);
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vlan_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(vlan_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    aim_free(entry->value.ports);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_vlan_entry_create,
    .entry_modify = pipeline_bvs_table_vlan_entry_modify,
    .entry_delete = pipeline_bvs_table_vlan_entry_delete,
    .entry_stats_get = pipeline_bvs_table_vlan_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_vlan_entry_hit_status_get,
};

void
pipeline_bvs_table_vlan_register(void)
{
    vlan_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_VLAN, "vlan", &table_ops, NULL);
}

void
pipeline_bvs_table_vlan_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_VLAN);
    bighash_table_destroy(vlan_hashtable, NULL);
}

struct vlan_entry *
pipeline_bvs_table_vlan_lookup(uint16_t vlan_vid)
{
    struct vlan_key key = { .vlan_vid = vlan_vid & ~VLAN_CFI_BIT};
    struct vlan_entry *entry = vlan_hashtable_first(vlan_hashtable, &key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit vlan entry vlan=%u -> l3_interface_class_id=%#x vrf=%u",
                        entry->key.vlan_vid, entry->value.l3_interface_class_id, entry->value.vrf);
    } else {
        AIM_LOG_VERBOSE("Miss vlan entry vlan=%u", key.vlan_vid);
    }
    return entry;
}
