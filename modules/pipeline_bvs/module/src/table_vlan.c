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

static void cleanup_value(struct vlan_value *value);

static bighash_table_t *vlan_hashtable;
static const of_match_fields_t required_mask = {
    .vlan_vid = 0xffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct vlan_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct vlan_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;
    bool tagged = true;
    int ports_size = 1;

    value->l3_interface_class_id = 0;
    value->vrf = 0;
    value->ports = aim_malloc(ports_size * sizeof(value->ports[0]));
    value->num_ports = 0;
    value->num_tagged_ports = 0;
    value->internal_priority = INTERNAL_PRIORITY_INVALID;

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
                case OF_ACTION_OUTPUT:
                    if (value->num_ports >= ports_size) {
                        ports_size *= 2;
                        value->ports = aim_realloc(value->ports, ports_size * sizeof(value->ports[0]));
                    }
                    of_action_output_port_get(&act, &value->ports[value->num_ports++]);
                    if (tagged) {
                        value->num_tagged_ports++;
                    }
                    break;
                case OF_ACTION_POP_VLAN:
                    tagged = false;
                    break;
                case OF_ACTION_SET_FIELD: {
                    of_object_t oxm;
                    of_action_set_field_field_bind(&act, &oxm);
                    switch (oxm.object_id) {
                    case OF_OXM_BSN_L3_INTERFACE_CLASS_ID:
                        of_oxm_bsn_l3_interface_class_id_value_get(&oxm, &value->l3_interface_class_id);
                        break;
                    case OF_OXM_BSN_VRF:
                        of_oxm_bsn_vrf_value_get(&oxm, &value->vrf);
                        break;
                    default:
                        AIM_LOG_ERROR("Unexpected set-field OXM %s in vlan table", of_object_id_str[oxm.object_id]);
                        goto error;
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in vlan table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        case OF_INSTRUCTION_BSN_INTERNAL_PRIORITY:
            of_instruction_bsn_internal_priority_value_get(&inst, &value->internal_priority);
            break;
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in vlan table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct vlan_value *value)
{
    aim_free(value->ports);
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

    AIM_LOG_VERBOSE("Create vlan entry vlan=%u -> l3_interface_class_id=%#x vrf=%u, internal_prio=%u",
                    entry->key.vlan_vid, entry->value.l3_interface_class_id, entry->value.vrf, entry->value.internal_priority);

    vlan_hashtable_insert(vlan_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
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

    cleanup_value(&entry->value);
    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vlan_entry *entry = entry_priv;

    stats_clear(ind_ovs_rx_vlan_stats_select(entry->key.vlan_vid));
    stats_clear(ind_ovs_tx_vlan_stats_select(entry->key.vlan_vid));

    bighash_remove(vlan_hashtable, &entry->hash_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
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
        packet_trace("Hit vlan entry vlan=%u -> l3_interface_class_id=%#x vrf=%u, internal_prio=%u",
                     entry->key.vlan_vid, entry->value.l3_interface_class_id, entry->value.vrf, entry->value.internal_priority);
    } else {
        packet_trace("Miss vlan entry vlan=%u", key.vlan_vid);
    }
    return entry;
}
