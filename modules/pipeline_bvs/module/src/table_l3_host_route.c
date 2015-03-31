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

#define TEMPLATE_NAME l3_host_route_hashtable
#define TEMPLATE_OBJ_TYPE struct l3_host_route_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static void cleanup_value(struct l3_host_route_value *value);

static bighash_table_t *l3_host_route_hashtable;
static const of_match_fields_t required_mask = {
    .bsn_vrf = 0xffffffff,
    .eth_type = 0xffff,
    .ipv4_dst = 0xffffffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct l3_host_route_key *key)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    key->vrf = match.fields.bsn_vrf;
    key->ipv4 = match.fields.ipv4_dst;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct l3_host_route_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    value->cpu = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.object_id) {
        case OF_INSTRUCTION_WRITE_ACTIONS: {
            of_list_action_t actions;
            of_instruction_write_actions_actions_bind(&inst, &actions);

            if (pipeline_bvs_parse_next_hop(&actions, &value->next_hop) < 0) {
                AIM_LOG_ERROR("Failed to parse next-hop in L3 host table");
                goto error;
            }

            of_object_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.object_id) {
                case OF_ACTION_GROUP:
                case OF_ACTION_BSN_GENTABLE:
                case OF_ACTION_DEC_NW_TTL:
                    /* Handled by pipeline_bvs_parse_next_hop */
                    break;
                case OF_ACTION_SET_FIELD: {
                    of_object_t oxm;
                    of_action_set_field_field_bind(&act, &oxm);
                    switch (oxm.object_id) {
                    case OF_OXM_VLAN_VID:
                    case OF_OXM_ETH_SRC:
                    case OF_OXM_ETH_DST:
                        /* Handled by pipeline_bvs_parse_next_hop */
                        break;
                    default:
                        AIM_LOG_ERROR("Unexpected set-field OXM %s in l3_host_route table", of_object_id_str[oxm.object_id]);
                        goto error;
                    }
                    break;
                }
                case OF_ACTION_OUTPUT: {
                    of_port_no_t port_no;
                    of_action_output_port_get(&act, &port_no);
                    switch (port_no) {
                        case OF_PORT_DEST_CONTROLLER: {
                            value->cpu = true;
                            break;
                        default:
                            AIM_LOG_ERROR("Unexpected output port %u in l3_host_route_table", port_no);
                            goto error;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in l3_host_route table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in l3_host_route table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct l3_host_route_value *value)
{
    pipeline_bvs_cleanup_next_hop(&value->next_hop);
}

static indigo_error_t
pipeline_bvs_table_l3_host_route_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct l3_host_route_entry *entry = aim_zmalloc(sizeof(*entry));

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

    l3_host_route_hashtable_insert(l3_host_route_hashtable, entry);

    AIM_LOG_VERBOSE("Create l3_host_route entry vrf=%u ip=%{ipv4a} -> next_hop=%{next_hop} cpu=%d",
                    entry->key.vrf, entry->key.ipv4,
                    &entry->value.next_hop, entry->value.cpu);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_host_route_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct l3_host_route_entry *entry = entry_priv;
    struct l3_host_route_value value;

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
pipeline_bvs_table_l3_host_route_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct l3_host_route_entry *entry = entry_priv;

    bighash_remove(l3_host_route_hashtable, &entry->hash_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_host_route_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_host_route_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_l3_host_route_entry_create,
    .entry_modify = pipeline_bvs_table_l3_host_route_entry_modify,
    .entry_delete = pipeline_bvs_table_l3_host_route_entry_delete,
    .entry_stats_get = pipeline_bvs_table_l3_host_route_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_l3_host_route_entry_hit_status_get,
};

void
pipeline_bvs_table_l3_host_route_register(void)
{
    l3_host_route_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_L3_HOST_ROUTE, "l3_host_route", &table_ops, NULL);
}

void
pipeline_bvs_table_l3_host_route_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_L3_HOST_ROUTE);
    bighash_table_destroy(l3_host_route_hashtable, NULL);
}

struct l3_host_route_entry *
pipeline_bvs_table_l3_host_route_lookup(uint32_t vrf, uint32_t ipv4)
{
    struct l3_host_route_key key = { .vrf=vrf, .ipv4 = ntohl(ipv4) };
    struct l3_host_route_entry *entry = l3_host_route_hashtable_first(l3_host_route_hashtable, &key);
    if (entry) {
        packet_trace("Hit l3_host_route entry vrf=%u ip=%{ipv4a} -> next_hop=%{next_hop} cpu=%d",
                        entry->key.vrf, entry->key.ipv4,
                        &entry->value.next_hop, entry->value.cpu);
    } else {
        packet_trace("Miss l3_host_route entry vrf=%u ip=%{ipv4a}",
                        key.vrf, key.ipv4);
    }
    return entry;
}
