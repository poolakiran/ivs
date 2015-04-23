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

#define TEMPLATE_NAME floating_ip_forward_hashtable
#define TEMPLATE_OBJ_TYPE struct floating_ip_forward_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *floating_ip_forward_hashtable;
static const of_match_fields_t required_mask = {
    .vlan_vid = 0xffff,
    .ipv4_src = 0xffffffff,
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};
static const of_match_fields_t required_mask_eth_type = {
    .eth_type = 0xffff,
    .vlan_vid = 0xffff,
    .ipv4_src = 0xffffffff,
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct floating_ip_forward_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t)) &&
            memcmp(&match.masks, &required_mask_eth_type, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    key->ipv4_src = match.fields.ipv4_src;
    key->eth_dst = match.fields.eth_dst;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct floating_ip_forward_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    bool seen_new_vlan_vid = false;
    bool seen_new_ipv4_src = false;
    bool seen_new_eth_dst = false;
    bool seen_new_eth_src = false;

    memset(value, 0, sizeof(*value));

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
                case OF_ACTION_SET_FIELD: {
                    of_object_t oxm;
                    of_action_set_field_field_bind(&act, &oxm);
                    switch (oxm.object_id) {
                    case OF_OXM_VLAN_VID:
                        if (!seen_new_vlan_vid) {
                            of_oxm_vlan_vid_value_get(&oxm, &value->new_vlan_vid);
                            value->new_vlan_vid &= ~VLAN_CFI_BIT;
                            seen_new_vlan_vid = true;
                        } else {
                            AIM_LOG_ERROR("duplicate set-field vlan_vid action in floating_ip_forward table");
                            goto error;
                        }
                        break;
                    case OF_OXM_IPV4_SRC:
                        if (!seen_new_ipv4_src) {
                            of_oxm_ipv4_src_value_get(&oxm, &value->new_ipv4_src);
                            value->ipv4_netmask = -1;
                            seen_new_ipv4_src = true;
                        } else {
                            AIM_LOG_ERROR("duplicate set-field ipv4_src action in floating_ip_forward table");
                            goto error;
                        }
                        break;
                    case OF_OXM_IPV4_SRC_MASKED:
                        if (!seen_new_ipv4_src) {
                            of_oxm_ipv4_src_masked_value_get(&oxm, &value->new_ipv4_src);
                            of_oxm_ipv4_src_masked_value_mask_get(&oxm, &value->ipv4_netmask);
                            seen_new_ipv4_src = true;
                        } else {
                            AIM_LOG_ERROR("duplicate set-field ipv4_src action in floating_ip_forward table");
                            goto error;
                        }
                        break;
                    case OF_OXM_ETH_SRC:
                        if (!seen_new_eth_src) {
                            of_oxm_eth_src_value_get(&oxm, &value->new_eth_src);
                            seen_new_eth_src = true;
                        } else {
                            AIM_LOG_ERROR("duplicate set-field eth_src action in floating_ip_forward table");
                            goto error;
                        }
                        break;
                    case OF_OXM_ETH_DST:
                        if (!seen_new_eth_dst) {
                            of_oxm_eth_dst_value_get(&oxm, &value->new_eth_dst);
                            seen_new_eth_dst = true;
                        } else {
                            AIM_LOG_ERROR("duplicate set-field eth_dst action in floating_ip_forward table");
                            goto error;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in floating_ip_forward table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in floating_ip_forward table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    if (!seen_new_vlan_vid || !seen_new_ipv4_src || !seen_new_eth_dst || !seen_new_eth_src) {
        AIM_LOG_ERROR("Missing required action in floating_ip_forward table");
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bvs_table_floating_ip_forward_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct floating_ip_forward_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create floating_ip_forward entry vlan=%u ipv4_src=%{ipv4a} eth_dst=%{mac} -> "
                    "new_vlan=%u new_ipv4_src=%{ipv4a} new_eth_src=%{mac} new_eth_dst=%{mac} ipv4_netmask=%{ipv4a}",
                    entry->key.vlan_vid, entry->key.ipv4_src, &entry->key.eth_dst,
                    entry->value.new_vlan_vid, entry->value.new_ipv4_src, &entry->value.new_eth_src, &entry->value.new_eth_dst,
                    entry->value.ipv4_netmask);

    floating_ip_forward_hashtable_insert(floating_ip_forward_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_floating_ip_forward_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct floating_ip_forward_entry *entry = entry_priv;
    struct floating_ip_forward_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_floating_ip_forward_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct floating_ip_forward_entry *entry = entry_priv;

    bighash_remove(floating_ip_forward_hashtable, &entry->hash_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_floating_ip_forward_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_floating_ip_forward_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_floating_ip_forward_entry_create,
    .entry_modify = pipeline_bvs_table_floating_ip_forward_entry_modify,
    .entry_delete = pipeline_bvs_table_floating_ip_forward_entry_delete,
    .entry_stats_get = pipeline_bvs_table_floating_ip_forward_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_floating_ip_forward_entry_hit_status_get,
};

void
pipeline_bvs_table_floating_ip_forward_register(void)
{
    floating_ip_forward_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_FLOATING_IP_FORWARD, "floating_ip_forward", &table_ops, NULL);
}

void
pipeline_bvs_table_floating_ip_forward_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_FLOATING_IP_FORWARD);
    bighash_table_destroy(floating_ip_forward_hashtable, NULL);
}

struct floating_ip_forward_entry *
pipeline_bvs_table_floating_ip_forward_lookup(uint16_t vlan_vid, uint32_t ipv4_src, const uint8_t *eth_dst)
{
    struct floating_ip_forward_key key = {
        .vlan_vid = vlan_vid & ~VLAN_CFI_BIT,
        .ipv4_src = ipv4_src,
    };
    memcpy(&key.eth_dst, eth_dst, OF_MAC_ADDR_BYTES);
    struct floating_ip_forward_entry *entry = floating_ip_forward_hashtable_first(floating_ip_forward_hashtable, &key);
    if (entry) {
        packet_trace("Hit floating_ip_forward entry vlan=%u ipv4_src=%{ipv4a} eth_dst=%{mac} -> "
                     "new_vlan=%u new_ipv4_src=%{ipv4a} new_eth_src=%{mac} new_eth_dst=%{mac} ipv4_netmask=%{ipv4a}",
                     entry->key.vlan_vid, entry->key.ipv4_src, &entry->key.eth_dst,
                     entry->value.new_vlan_vid, entry->value.new_ipv4_src, &entry->value.new_eth_src, &entry->value.new_eth_dst, entry->value.ipv4_netmask);
    } else {
        packet_trace("Miss floating_ip_forward entry vlan=%u ipv4_src=%{ipv4a} eth_dst=%{mac}",
                     key.vlan_vid, key.ipv4_src, &key.eth_dst);
    }
    return entry;
}
