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
#include <linux/if_ether.h>
#include <lpm/lpm.h>

#define MAX_VRF 1024

static void cleanup_value(struct l3_cidr_route_value *value);

static const of_match_fields_t maximum_mask = {
    .bsn_vrf = 0xffffffff,
    .eth_type = 0xffff,
    .ipv4_dst = 0xffffffff,
};
static const of_match_fields_t minimum_mask = {
    .bsn_vrf = 0xffffffff,
    .eth_type = 0xffff,
};

static struct lpm_trie *lpm_tries[MAX_VRF+1];

static indigo_error_t
parse_key(of_flow_add_t *obj, struct l3_cidr_route_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (match.fields.eth_type != ETH_P_IP) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    uint16_t priority;
    of_flow_add_priority_get(obj, &priority);

    if (priority == 0) {
        /* Avoid shifting by the field width */
        if (match.masks.ipv4_dst != 0) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    } else {
        if (match.masks.ipv4_dst != (0xffffffff << (32 - priority))) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    key->vrf = match.fields.bsn_vrf;
    if (key->vrf > MAX_VRF) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    key->ipv4 = match.fields.ipv4_dst;
    key->mask_len = priority;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct l3_cidr_route_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;

    value->cpu = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.header.object_id) {
        case OF_INSTRUCTION_WRITE_ACTIONS: {
            of_list_action_t actions;
            of_instruction_write_actions_actions_bind(&inst.write_actions, &actions);

            if (pipeline_bvs_parse_next_hop(&actions, &value->next_hop) < 0) {
                AIM_LOG_ERROR("Failed to parse next-hop in L3 CIDR table");
                goto error;
            }

            of_action_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.header.object_id) {
                case OF_ACTION_GROUP:
                    /* Handled by pipeline_bvs_parse_next_hop */
                    break;
                case OF_ACTION_SET_FIELD: {
                    of_oxm_t oxm;
                    of_action_set_field_field_bind(&act.set_field, &oxm.header);
                    switch (oxm.header.object_id) {
                    case OF_OXM_VLAN_VID:
                    case OF_OXM_ETH_SRC:
                    case OF_OXM_ETH_DST:
                        /* Handled by pipeline_bvs_parse_next_hop */
                        break;
                    default:
                        AIM_LOG_ERROR("Unexpected set-field OXM %s in l3_cidr_route table", of_object_id_str[oxm.header.object_id]);
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_OUTPUT: {
                    of_port_no_t port_no;
                    of_action_output_port_get(&act.output, &port_no);
                    switch (port_no) {
                        case OF_PORT_DEST_CONTROLLER: {
                            value->cpu = true;
                            break;
                        default:
                            AIM_LOG_ERROR("Unexpected output port %u in l3_cidr_route_table", port_no);
                            goto error;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in l3_cidr_route table", of_object_id_str[act.header.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in l3_cidr_route table", of_object_id_str[inst.header.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct l3_cidr_route_value *value)
{
    pipeline_bvs_cleanup_next_hop(&value->next_hop);
}

static void
l3_cidr_route_insert(struct l3_cidr_route_entry *entry)
{
    if (lpm_tries[entry->key.vrf] == NULL) {
        lpm_tries[entry->key.vrf] = lpm_trie_create();
    }

    lpm_trie_insert(lpm_tries[entry->key.vrf], entry->key.ipv4,
                    entry->key.mask_len, entry);
}

static void
l3_cidr_route_remove(struct l3_cidr_route_entry *entry)
{
    lpm_trie_remove(lpm_tries[entry->key.vrf], entry->key.ipv4,
                    entry->key.mask_len);

    if (lpm_trie_is_empty(lpm_tries[entry->key.vrf])) {
        lpm_trie_destroy(lpm_tries[entry->key.vrf]);
        lpm_tries[entry->key.vrf] = NULL;
    }
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct l3_cidr_route_entry *entry = aim_zmalloc(sizeof(*entry));

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

    AIM_LOG_VERBOSE("Create l3_cidr_route entry prio=%u vrf=%u ipv4=%{ipv4a}/%u"
                    " -> next_hop=%{next_hop} cpu=%d",
                    entry->key.mask_len, entry->key.vrf, entry->key.ipv4,
                    entry->key.mask_len, &entry->value.next_hop, entry->value.cpu);

    ind_ovs_fwd_write_lock();
    l3_cidr_route_insert(entry);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct l3_cidr_route_entry *entry = entry_priv;
    struct l3_cidr_route_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&entry->value);
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct l3_cidr_route_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    l3_cidr_route_remove(entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_l3_cidr_route_entry_create,
    .entry_modify = pipeline_bvs_table_l3_cidr_route_entry_modify,
    .entry_delete = pipeline_bvs_table_l3_cidr_route_entry_delete,
    .entry_stats_get = pipeline_bvs_table_l3_cidr_route_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_l3_cidr_route_entry_hit_status_get,
};

void
pipeline_bvs_table_l3_cidr_route_register(void)
{
    indigo_core_table_register(TABLE_ID_L3_CIDR_ROUTE, "l3_cidr_route", &table_ops, NULL);
}

void
pipeline_bvs_table_l3_cidr_route_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_L3_CIDR_ROUTE);
}

struct l3_cidr_route_entry *
pipeline_bvs_table_l3_cidr_route_lookup(uint32_t vrf, uint32_t ipv4)
{
    struct l3_cidr_route_entry *entry = NULL;
    if (lpm_tries[vrf]) {
        entry = lpm_trie_search(lpm_tries[vrf], ntohl(ipv4));
    }

    if (entry) {
        AIM_LOG_VERBOSE("Hit l3_cidr_route entry prio=%u vrf=%u ipv4=%{ipv4a}/%u"
                        " -> next_hop=%{next_hop} cpu=%d",
                        entry->key.mask_len, entry->key.vrf, entry->key.ipv4,
                        entry->key.mask_len, &entry->value.next_hop, entry->value.cpu);
    } else {
        AIM_LOG_VERBOSE("Miss l3_cidr_route entry vrf=%u ipv4=%{ipv4a}", vrf, ntohl(ipv4));
    }

    return entry;
}
