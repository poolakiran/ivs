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

#define TEMPLATE_NAME l2_hashtable
#define TEMPLATE_OBJ_TYPE struct l2_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *l2_hashtable;
static const of_match_fields_t required_mask = {
    .vlan_vid = 0xffff,
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct l2_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_COMPAT;
    }
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    key->mac = match.fields.eth_dst;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct l2_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;

    value->lag = NULL;

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
                case OF_ACTION_GROUP: {
                    uint32_t lag_id;
                    of_action_group_group_id_get(&act.group, &lag_id);
                    value->lag = pipeline_bvs_group_lag_acquire(lag_id);
                    if (value->lag == NULL) {
                        AIM_LOG_WARN("Nonexistent LAG in L2 table");
                        break;
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in L2 table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        default:
            AIM_LOG_WARN("Unexpected instruction %s in L2 table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct l2_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create L2 entry vlan=%u, mac=%{mac} -> lag %u",
                    entry->key.vlan_vid, &entry->key.mac,
                    entry->value.lag ? entry->value.lag->id : OF_GROUP_ANY);

    ind_ovs_fwd_write_lock();
    l2_hashtable_insert(l2_hashtable, entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct l2_entry *entry = entry_priv;
    struct l2_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    if (entry->value.lag != NULL) {
        pipeline_bvs_group_lag_release(entry->value.lag);
    }
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct l2_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    bighash_remove(l2_hashtable, &entry->hash_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    flow_stats->packets = entry->stats.packets;
    flow_stats->bytes = entry->stats.bytes;
    if (entry->value.lag != NULL) {
        pipeline_bvs_group_lag_release(entry->value.lag);
    }
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct l2_entry *entry = entry_priv;
    flow_stats->packets = entry->stats.packets;
    flow_stats->bytes = entry->stats.bytes;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    struct l2_entry *entry = entry_priv;
    if (entry->stats.packets != entry->last_hit_check_packets) {
        entry->last_hit_check_packets = entry->stats.packets;
        *hit_status = true;
    } else {
        *hit_status = false;
    }
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_l2_entry_create,
    .entry_modify = pipeline_bvs_table_l2_entry_modify,
    .entry_delete = pipeline_bvs_table_l2_entry_delete,
    .entry_stats_get = pipeline_bvs_table_l2_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_l2_entry_hit_status_get,
};

void
pipeline_bvs_table_l2_register(void)
{
    l2_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_L2, "l2", &table_ops, NULL);
}

void
pipeline_bvs_table_l2_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_L2);
    bighash_table_destroy(l2_hashtable, NULL);
}

struct l2_entry *
pipeline_bvs_table_l2_lookup(uint16_t vlan_vid, const uint8_t *mac)
{
    struct l2_key key;
    key.vlan_vid = VLAN_VID(vlan_vid);
    memcpy(&key.mac.addr, mac, OF_MAC_ADDR_BYTES);

    struct l2_entry *entry = l2_hashtable_first(l2_hashtable, &key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit L2 entry vlan=%u, mac=%{mac} -> lag %u",
                        entry->key.vlan_vid, &entry->key.mac,
                        entry->value.lag ? entry->value.lag->id : OF_GROUP_ANY);
    } else {
        AIM_LOG_VERBOSE("Miss L2 entry vlan=%u, mac=%{mac}",
                        key.vlan_vid, &key.mac);
    }
    return entry;
}
