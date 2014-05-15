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

#define TEMPLATE_NAME port_hashtable
#define TEMPLATE_OBJ_TYPE struct port_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *port_hashtable;
static const of_match_fields_t required_mask = {
    .in_port = 0xffffffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct port_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_COMPAT;
    }
    key->port = match.fields.in_port;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct port_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;

    value->lag_id = OF_GROUP_ANY;
    value->egr_port_group_id = 0;
    value->default_vlan_vid = 0;
    value->disable_src_mac_check = false;
    value->arp_offload = false;
    value->dhcp_offload = false;
    value->packet_of_death = false;
    value->prioritize_pdus = false;

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
                        of_oxm_vlan_vid_value_get(&oxm.vlan_vid, &value->default_vlan_vid);
                        break;
                    case OF_OXM_BSN_LAG_ID:
                        of_oxm_bsn_lag_id_value_get(&oxm.vlan_vid, &value->lag_id);
                        break;
                    case OF_OXM_BSN_EGR_PORT_GROUP_ID:
                        of_oxm_bsn_egr_port_group_id_value_get(&oxm.vlan_vid, &value->egr_port_group_id);
                        break;
                    default:
                        AIM_LOG_WARN("Unexpected set-field OXM %s in port table", of_object_id_str[oxm.header.object_id]);
                        break;
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in port table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        case OF_INSTRUCTION_BSN_DISABLE_SRC_MAC_CHECK:
            value->disable_src_mac_check = true;
            break;
        case OF_INSTRUCTION_BSN_ARP_OFFLOAD:
            value->arp_offload = true;
            break;
        case OF_INSTRUCTION_BSN_DHCP_OFFLOAD:
            value->dhcp_offload = true;
            break;
        case OF_INSTRUCTION_BSN_PACKET_OF_DEATH:
            value->packet_of_death = true;
            break;
        case OF_INSTRUCTION_BSN_PRIORITIZE_PDUS:
            value->prioritize_pdus = true;
            break;
        default:
            AIM_LOG_WARN("Unexpected instruction %s in port table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_port_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct port_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create port entry port=%u -> lag_id=%u egr_port_group_id=%u default_vlan_vid=%u %s%s%s%s%s",
                    entry->key.port, entry->value.lag_id, entry->value.egr_port_group_id, entry->value.default_vlan_vid,
                    entry->value.disable_src_mac_check ? "disable_src_mac_check " : "",
                    entry->value.arp_offload ? "arp_offload " : "",
                    entry->value.dhcp_offload ? "dhcp_offload " : "",
                    entry->value.packet_of_death ? "packet_of_death " : "",
                    entry->value.prioritize_pdus ? "prioritize_pdus " : "");

    ind_ovs_fwd_write_lock();
    port_hashtable_insert(port_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_port_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct port_entry *entry = entry_priv;
    struct port_value value;

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
pipeline_bvs_table_port_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct port_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(port_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_port_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static indigo_error_t
pipeline_bvs_table_port_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_port_entry_create,
    .entry_modify = pipeline_bvs_table_port_entry_modify,
    .entry_delete = pipeline_bvs_table_port_entry_delete,
    .entry_stats_get = pipeline_bvs_table_port_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_port_entry_hit_status_get,
};

void
pipeline_bvs_table_port_register(void)
{
    port_hashtable = bighash_table_create(64);
    indigo_core_table_register(TABLE_ID_PORT, "port", &table_ops, NULL);
}

void
pipeline_bvs_table_port_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_PORT);
    bighash_table_destroy(port_hashtable, NULL);
}

struct port_entry *
pipeline_bvs_table_port_lookup(const struct port_key *key)
{
    struct port_entry *entry = port_hashtable_first(port_hashtable, key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit port entry port=%u -> lag_id=%u egr_port_group_id=%u default_vlan_vid=%u %s%s%s%s%s",
                        entry->key.port, entry->value.lag_id, entry->value.egr_port_group_id, entry->value.default_vlan_vid,
                        entry->value.disable_src_mac_check ? "disable_src_mac_check " : "",
                        entry->value.arp_offload ? "arp_offload " : "",
                        entry->value.dhcp_offload ? "dhcp_offload " : "",
                        entry->value.packet_of_death ? "packet_of_death " : "",
                        entry->value.prioritize_pdus ? "prioritize_pdus " : "");
    } else {
        AIM_LOG_VERBOSE("Miss port entry port=%u", key->port);
    }
    return entry;
}
