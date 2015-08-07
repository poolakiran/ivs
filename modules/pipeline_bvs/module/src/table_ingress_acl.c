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
    .bsn_tcp_flags = 0xffff,
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
        return INDIGO_ERROR_BAD_MATCH;
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

    key->tcp_flags = mask->tcp_flags = 0;
    key->pad2 = mask->pad2 = 0;
    if (key->ip_proto == IPPROTO_TCP) {
        key->tp_src = match.fields.tcp_src;
        mask->tp_src = match.masks.tcp_src;
        key->tp_dst = match.fields.tcp_dst;
        mask->tp_dst = match.masks.tcp_dst;
        key->tcp_flags = match.fields.bsn_tcp_flags;
        mask->tcp_flags = match.masks.bsn_tcp_flags;
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
    of_object_t inst;

    value->next_hop.type = NEXT_HOP_TYPE_NULL;
    value->cpu = false;
    value->drop = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.object_id) {
        case OF_INSTRUCTION_WRITE_ACTIONS: {
            of_list_action_t actions;
            of_instruction_write_actions_actions_bind(&inst, &actions);

            if (pipeline_bvs_parse_next_hop(&actions, &value->next_hop) < 0) {
                AIM_LOG_ERROR("Failed to parse next-hop in ingress_acl table");
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
                            AIM_LOG_ERROR("Unexpected output port %u in ingress_acl_table", port_no);
                            goto error;
                        }
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in ingress_acl table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        case OF_INSTRUCTION_BSN_DENY:
            value->drop = true;
            break;
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in ingress_acl table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    pipeline_bvs_cleanup_next_hop(&value->next_hop);
    return INDIGO_ERROR_BAD_ACTION;
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

    AIM_LOG_VERBOSE("Create ingress_acl entry prio=%u in_port=%u/%#x vlan_vid=%u/%#x ip_proto=%u/%#x vrf=%u/%#x l3_interface_class_id=%u/%#x l3_src_class_id=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x",
                    priority, key.in_port, mask.in_port, key.vlan_vid, mask.vlan_vid, key.ip_proto, mask.ip_proto, key.vrf, mask.vrf, key.l3_interface_class_id, mask.l3_interface_class_id, key.l3_src_class_id, mask.l3_src_class_id, key.ipv4_src, mask.ipv4_src, key.ipv4_dst, mask.ipv4_dst, key.tp_src, mask.tp_src, key.tp_dst, mask.tp_dst, key.tcp_flags, mask.tcp_flags);
    AIM_LOG_VERBOSE("  next_hop=%{next_hop} cpu=%d drop=%d",
                    &entry->value.next_hop, entry->value.cpu, entry->value.drop);

    stats_alloc(&entry->stats_handle);

    tcam_insert(ingress_acl_tcam, &entry->tcam_entry, &key, &mask, priority);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
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

    pipeline_bvs_cleanup_next_hop(&entry->value.next_hop);
    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ingress_acl_entry *entry = entry_priv;

    tcam_remove(ingress_acl_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    pipeline_bvs_cleanup_next_hop(&entry->value.next_hop);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_ingress_acl_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct ingress_acl_entry *entry = entry_priv;
    struct stats stats;
    stats_get(&entry->stats_handle, &stats);
    flow_stats->packets = stats.packets;
    flow_stats->bytes = stats.bytes;
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
        packet_trace("Hit ingress_acl entry prio=%u in_port=%u/%#x vlan_vid=%u/%#x ip_proto=%u/%#x vrf=%u/%#x l3_interface_class_id=%u/%#x l3_src_class_id=%u/%#x ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} tp_src=%u/%#x tp_dst=%u/%#x tcp_flags=%#x/%#x",
                     tcam_entry->priority, entry_key->in_port, entry_mask->in_port, entry_key->vlan_vid, entry_mask->vlan_vid, entry_key->ip_proto, entry_mask->ip_proto, entry_key->vrf, entry_mask->vrf, entry_key->l3_interface_class_id, entry_mask->l3_interface_class_id, entry_key->l3_src_class_id, entry_mask->l3_src_class_id, entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst, entry_key->tp_src, entry_mask->tp_src, entry_key->tp_dst, entry_mask->tp_dst, entry_key->tcp_flags, entry_mask->tcp_flags);
        packet_trace("  next_hop=%{next_hop} cpu=%d drop=%d",
                     &entry->value.next_hop, entry->value.cpu, entry->value.drop);
        return entry;
    } else {
        packet_trace("Miss ingress_acl entry in_port=%u vlan_vid=%u ip_proto=%u vrf=%u l3_interface_class_id=%u l3_src_class_id=%u ipv4_src=%{ipv4a} ipv4_dst=%{ipv4a} tp_src=%u tp_dst=%u tcp_flags=%#x",
                     key->in_port, key->vlan_vid, key->ip_proto, key->vrf, key->l3_interface_class_id, key->l3_src_class_id, key->ipv4_src, key->ipv4_dst, key->tp_src, key->tp_dst, key->tcp_flags);
        return NULL;
    }
}
