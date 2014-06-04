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

static struct tcam *l3_cidr_route_tcam;
static const of_match_fields_t maximum_mask = {
    .bsn_vrf = 0xffffffff,
    .eth_type = 0xffff,
    .ipv4_dst = 0xffffffff,
};
static const of_match_fields_t minimum_mask = {
    .bsn_vrf = 0xffffffff,
    .eth_type = 0xffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct l3_cidr_route_key *key,
          struct l3_cidr_route_key *mask, uint16_t *priority)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (match.fields.eth_type != ETH_P_IP) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    of_flow_add_priority_get(obj, priority);

    if (*priority == 0) {
        /* Avoid shifting by the field width */
        if (match.masks.ipv4_dst != 0) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    } else {
        if (match.masks.ipv4_dst != (0xffffffff << (32 - *priority))) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    key->vrf = match.fields.bsn_vrf;
    mask->vrf = match.masks.bsn_vrf;

    key->ipv4 = match.fields.ipv4_dst;
    mask->ipv4 = match.masks.ipv4_dst;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct l3_cidr_route_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;
    bool seen_group = false;
    bool seen_new_vlan_vid = false;
    bool seen_new_eth_src = false;
    bool seen_new_eth_dst = false;

    value->cpu = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.header.object_id) {
        case OF_INSTRUCTION_WRITE_ACTIONS: {
            of_list_action_t actions;
            of_instruction_write_actions_actions_bind(&inst.write_actions, &actions);
            of_action_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.header.object_id) {
                case OF_ACTION_GROUP:
                    of_action_group_group_id_get(&act.group, &value->next_hop.group_id);
                    seen_group = true;
                    break;
                case OF_ACTION_SET_FIELD: {
                    of_oxm_t oxm;
                    of_action_set_field_field_bind(&act.set_field, &oxm.header);
                    switch (oxm.header.object_id) {
                    case OF_OXM_VLAN_VID:
                        of_oxm_vlan_vid_value_get(&oxm.vlan_vid, &value->next_hop.new_vlan_vid);
                        value->next_hop.new_vlan_vid &= ~VLAN_CFI_BIT;
                        seen_new_vlan_vid = true;
                        break;
                    case OF_OXM_ETH_SRC:
                        of_oxm_eth_src_value_get(&oxm.eth_src, &value->next_hop.new_eth_src);
                        seen_new_eth_src = true;
                        break;
                    case OF_OXM_ETH_DST:
                        of_oxm_eth_dst_value_get(&oxm.eth_dst, &value->next_hop.new_eth_dst);
                        seen_new_eth_dst = true;
                        break;
                    default:
                        AIM_LOG_WARN("Unexpected set-field OXM %s in l3_cidr_route table", of_object_id_str[oxm.header.object_id]);
                        break;
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
                            AIM_LOG_WARN("Unexpected output port %u in l3_cidr_route_table", port_no);
                            break;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in l3_cidr_route table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        default:
            AIM_LOG_WARN("Unexpected instruction %s in l3_cidr_route table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    if (seen_group) {
        switch (group_to_table_id(value->next_hop.group_id)) {
        case GROUP_TABLE_ID_LAG:
            if (!seen_new_vlan_vid || !seen_new_eth_src || !seen_new_eth_dst) {
                AIM_LOG_WARN("Missing required next-hop action in l3_cidr_route table");
                return INDIGO_ERROR_BAD_ACTION;
            }
            break;
        case GROUP_TABLE_ID_ECMP:
            if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
                AIM_LOG_WARN("Unexpected next-hop action in l3_cidr_route table");
            }
            break;
        default:
            AIM_LOG_WARN("Unexpected group table ID in l3_cidr_route table");
            return INDIGO_ERROR_BAD_ACTION;
        }
    } else {
        /* No group action, null route */
        value->next_hop.group_id = OF_GROUP_ANY;

        if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
            AIM_LOG_WARN("Unexpected next-hop action in l3_cidr_route table");
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct l3_cidr_route_entry *entry = aim_zmalloc(sizeof(*entry));
    struct l3_cidr_route_key key;
    struct l3_cidr_route_key mask;
    uint16_t priority;

    rv = parse_key(obj, &key, &mask, &priority);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    rv = parse_value(obj, &entry->value);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create l3_cidr_route entry prio=%u vrf=%u ipv4=%{ipv4a}/%{ipv4a}"
                    " -> group=%u vlan=%u eth-src=%{mac} eth-dst=%{mac} cpu=%d",
                    priority, key.vrf, key.ipv4, mask.ipv4,
                    entry->value.next_hop.group_id, entry->value.next_hop.new_vlan_vid, &entry->value.next_hop.new_eth_src, &entry->value.next_hop.new_eth_dst, entry->value.cpu);

    ind_ovs_fwd_write_lock();
    tcam_insert(l3_cidr_route_tcam, &entry->tcam_entry, &key, &mask, priority);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
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
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l3_cidr_route_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct l3_cidr_route_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    tcam_remove(l3_cidr_route_tcam, &entry->tcam_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
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
    l3_cidr_route_tcam = tcam_create(sizeof(struct l3_cidr_route_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_L3_CIDR_ROUTE, "l3_cidr_route", &table_ops, NULL);
}

void
pipeline_bvs_table_l3_cidr_route_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_L3_CIDR_ROUTE);
    tcam_destroy(l3_cidr_route_tcam);
}

struct l3_cidr_route_entry *
pipeline_bvs_table_l3_cidr_route_lookup(const struct l3_cidr_route_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(l3_cidr_route_tcam, key);
    if (tcam_entry) {
        struct l3_cidr_route_entry *entry = container_of(tcam_entry, tcam_entry, struct l3_cidr_route_entry);
        const struct l3_cidr_route_key *entry_key = tcam_entry->key;
        const struct l3_cidr_route_key *entry_mask = tcam_entry->mask;
        AIM_LOG_VERBOSE("Hit l3_cidr_route entry prio=%u vrf=%u ipv4=%{ipv4a}/%{ipv4a}"
                        " -> group=%u vlan=%u eth-src=%{mac} eth-dst=%{mac} cpu=%d",
                        tcam_entry->priority, entry_key->vrf, entry_key->ipv4, entry_mask->ipv4,
                        entry->value.next_hop.group_id, entry->value.next_hop.new_vlan_vid, &entry->value.next_hop.new_eth_src, &entry->value.next_hop.new_eth_dst, entry->value.cpu);
        return entry;
    } else {
        AIM_LOG_VERBOSE("Miss l3_cidr_route entry vrf=%u ipv4=%{ipv4a}", key->vrf, key->ipv4);
        return NULL;
    }
}
