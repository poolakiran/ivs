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

static struct tcam *ingress_acl_tcam;
static const of_match_fields_t maximum_mask = {
    .in_port = 0xffffffff,
    .eth_type = 0xffff,
    .vlan_vid = 0xffff,
    .bsn_vrf = 0xffffffff,
    .bsn_l3_interface_class_id = 0xffffffff,
    .bsn_l3_src_class_id = 0xffffffff,
    .ipv4_src = 0xffffffff,
    .ipv4_dst = 0xffffffff,
    .ip_proto = 0xff,
    .tcp_src = 0xffff,
    .tcp_dst = 0xffff,
    .udp_src = 0xffff,
    .udp_dst = 0xffff,
};
static const of_match_fields_t minimum_mask = {
    .eth_type = 0xffff,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct ingress_acl_key *key,
          struct ingress_acl_key *mask, uint16_t *priority)
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

    if (match.masks.ip_proto) {
        if (match.masks.ip_proto != 0xff) {
            return INDIGO_ERROR_BAD_MATCH;
        }

        if (match.fields.ip_proto != IPPROTO_TCP &&
                match.fields.ip_proto != IPPROTO_UDP) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_TCP) {
        if (match.masks.tcp_src || match.masks.tcp_dst) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.fields.ip_proto != IPPROTO_UDP) {
        if (match.masks.udp_src || match.masks.udp_dst) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    }

    if (match.masks.in_port && match.masks.in_port != 0xffffffff) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    of_flow_add_priority_get(obj, priority);

    key->in_port = match.fields.in_port;
    mask->in_port = match.masks.in_port;

    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    mask->vlan_vid = match.masks.vlan_vid;

    key->ip_proto = match.fields.ip_proto;
    mask->ip_proto = match.masks.ip_proto;

    key->pad = mask->pad = 0;

    key->vrf = match.fields.bsn_vrf;
    mask->vrf = match.masks.bsn_vrf;

    key->l3_interface_class_id = match.fields.bsn_l3_interface_class_id;
    mask->l3_interface_class_id = match.masks.bsn_l3_interface_class_id;

    key->l3_src_class_id = match.fields.bsn_l3_src_class_id;
    mask->l3_src_class_id = match.masks.bsn_l3_src_class_id;

    key->ipv4_src = match.fields.ipv4_src;
    mask->ipv4_src = match.masks.ipv4_src;

    key->ipv4_dst = match.fields.ipv4_dst;
    mask->ipv4_dst = match.masks.ipv4_dst;

    if (key->ip_proto == IPPROTO_TCP) {
        key->tp_src = match.fields.tcp_src;
        mask->tp_src = match.masks.tcp_src;
        key->tp_dst = match.fields.tcp_dst;
        mask->tp_dst = match.masks.tcp_dst;
    } else if (key->ip_proto == IPPROTO_UDP) {
        key->tp_src = match.fields.udp_src;
        mask->tp_src = match.masks.udp_src;
        key->tp_dst = match.fields.udp_dst;
        mask->tp_dst = match.masks.udp_dst;
    } else {
        key->tp_src = mask->tp_src = 0;
        key->tp_dst = mask->tp_dst = 0;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct ingress_acl_value *value)
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
                        AIM_LOG_WARN("Unexpected set-field OXM %s in ingress_acl table", of_object_id_str[oxm.header.object_id]);
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
                            AIM_LOG_WARN("Unexpected output port %u in ingress_acl_table", port_no);
                            break;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_WARN("Unexpected action %s in ingress_acl table", of_object_id_str[act.header.object_id]);
                    break;
                }
            }
            break;
        }
        case OF_INSTRUCTION_BSN_DENY:
            value->drop = true;
            break;
        default:
            AIM_LOG_WARN("Unexpected instruction %s in ingress_acl table", of_object_id_str[inst.header.object_id]);
            break;
        }
    }

    if (seen_group) {
        switch (group_to_table_id(value->next_hop.group_id)) {
        case GROUP_TABLE_ID_LAG:
            if (!seen_new_vlan_vid || !seen_new_eth_src || !seen_new_eth_dst) {
                AIM_LOG_WARN("Missing required next-hop action in ingress_acl table");
                return INDIGO_ERROR_BAD_ACTION;
            }
            break;
        case GROUP_TABLE_ID_ECMP:
            if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
                AIM_LOG_WARN("Unexpected next-hop action in ingress_acl table");
            }
            break;
        default:
            AIM_LOG_WARN("Unexpected group table ID in ingress_acl table");
            return INDIGO_ERROR_BAD_ACTION;
        }
    } else {
        /* No group action, null route */
        value->next_hop.group_id = OF_GROUP_ANY;

        if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
            AIM_LOG_WARN("Unexpected next-hop action in ingress_acl table");
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct ingress_acl_entry *entry = aim_zmalloc(sizeof(*entry));
    struct ingress_acl_key key;
    struct ingress_acl_key mask;
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

    AIM_LOG_VERBOSE("Create ingress_acl entry prio=%u in_port=%u/%#x vlan_vid=%u/%#x ip_proto=%u/%#x vrf=%u/%#x l3_interface_class_id=%u/%#x l3_src_class_id=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} tp_src=%u/%#x tp_dst=%u/%#x"
                    " -> group=%u vlan=%u eth-src=%{mac} eth-dst=%{mac} cpu=%d drop=%d",
                    priority, key.in_port, mask.in_port, key.vlan_vid, mask.vlan_vid, key.ip_proto, mask.ip_proto, key.vrf, mask.vrf, key.l3_interface_class_id, mask.l3_interface_class_id, key.l3_src_class_id, mask.l3_src_class_id, key.ipv4_src, mask.ipv4_src, key.ipv4_dst, mask.ipv4_dst, key.tp_src, mask.tp_src, key.tp_dst, mask.tp_dst,
                    entry->value.next_hop.group_id, entry->value.next_hop.new_vlan_vid, &entry->value.next_hop.new_eth_src, &entry->value.next_hop.new_eth_dst, entry->value.cpu, entry->value.drop);

    ind_ovs_fwd_write_lock();
    tcam_insert(ingress_acl_tcam, &entry->tcam_entry, &key, &mask, priority);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct ingress_acl_entry *entry = entry_priv;
    struct ingress_acl_value value;

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
pipeline_bvs_table_ingress_acl_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ingress_acl_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    tcam_remove(ingress_acl_tcam, &entry->tcam_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_ingress_acl_entry_create,
    .entry_modify = pipeline_bvs_table_ingress_acl_entry_modify,
    .entry_delete = pipeline_bvs_table_ingress_acl_entry_delete,
    .entry_stats_get = pipeline_bvs_table_ingress_acl_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_ingress_acl_entry_hit_status_get,
};

void
pipeline_bvs_table_ingress_acl_register(void)
{
    ingress_acl_tcam = tcam_create(sizeof(struct ingress_acl_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_INGRESS_ACL, "ingress_acl", &table_ops, NULL);
}

void
pipeline_bvs_table_ingress_acl_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_INGRESS_ACL);
    tcam_destroy(ingress_acl_tcam);
}

struct ingress_acl_entry *
pipeline_bvs_table_ingress_acl_lookup(const struct ingress_acl_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(ingress_acl_tcam, key);
    if (tcam_entry) {
        struct ingress_acl_entry *entry = container_of(tcam_entry, tcam_entry, struct ingress_acl_entry);
        const struct ingress_acl_key *entry_key = tcam_entry->key;
        const struct ingress_acl_key *entry_mask = tcam_entry->mask;
        AIM_LOG_VERBOSE("Hit ingress_acl entry prio=%u in_port=%u/%#x vlan_vid=%u/%#x ip_proto=%u/%#x vrf=%u/%#x l3_interface_class_id=%u/%#x l3_src_class_id=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} tp_src=%u/%#x tp_dst=%u/%#x"
                        " -> group=%u vlan=%u eth-src=%{mac} eth-dst=%{mac} cpu=%d drop=%d",
                        tcam_entry->priority, entry_key->in_port, entry_mask->in_port, entry_key->vlan_vid, entry_mask->vlan_vid, entry_key->ip_proto, entry_mask->ip_proto, entry_key->vrf, entry_mask->vrf, entry_key->l3_interface_class_id, entry_mask->l3_interface_class_id, entry_key->l3_src_class_id, entry_mask->l3_src_class_id, entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst,
                        entry->value.next_hop.group_id, entry->value.next_hop.new_vlan_vid, &entry->value.next_hop.new_eth_src, &entry->value.next_hop.new_eth_dst, entry->value.cpu, entry->value.drop);
        return entry;
    } else {
        AIM_LOG_VERBOSE("Miss ingress_acl entry in_port=%u vlan_vid=%u ip_proto=%u vrf=%u l3_interface_class_id=%u l3_src_class_id=%u ipv4_src=%{ipv4a} ipv4_dst=%{ipv4a} tp_src=%u tp_dst=%u",
                        key->in_port, key->vlan_vid, key->ip_proto, key->vrf, key->l3_interface_class_id, key->l3_src_class_id, key->ipv4_src, key->ipv4_dst, key->tp_src, key->tp_dst);
        return NULL;
    }
}