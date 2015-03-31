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

static struct tcam *vlan_acl_tcam;
static const of_match_fields_t maximum_mask = {
    .vlan_vid = 0xffff,
    .eth_src = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};
static const of_match_fields_t minimum_mask = {
    .vlan_vid = 0x0000,
    .eth_src = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    .eth_dst = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct vlan_acl_key *key, struct vlan_acl_key *mask)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    mask->vlan_vid = match.masks.vlan_vid;

    key->eth_src = match.fields.eth_src;
    mask->eth_src = match.masks.eth_src;

    key->eth_dst = match.fields.eth_dst;
    mask->eth_dst = match.masks.eth_dst;

    key->pad = mask->pad = 0;

    uint16_t priority;
    of_flow_add_priority_get(obj, &priority);
    if (priority != 0) {
        return INDIGO_ERROR_COMPAT;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct vlan_acl_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    value->l3_interface_class_id = 0;
    value->l3_src_class_id = 0;
    value->vrf = 0;

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
                    case OF_OXM_BSN_L3_INTERFACE_CLASS_ID:
                        of_oxm_bsn_l3_interface_class_id_value_get(&oxm, &value->l3_interface_class_id);
                        break;
                    case OF_OXM_BSN_L3_SRC_CLASS_ID:
                        of_oxm_bsn_l3_src_class_id_value_get(&oxm, &value->l3_src_class_id);
                        break;
                    case OF_OXM_BSN_VRF:
                        of_oxm_bsn_vrf_value_get(&oxm, &value->vrf);
                        break;
                    default:
                        AIM_LOG_ERROR("Unexpected set-field OXM %s in vlan_acl table", of_object_id_str[oxm.object_id]);
                        goto error;
                    }
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in vlan_acl table", of_object_id_str[act.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in vlan_acl table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bvs_table_vlan_acl_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct vlan_acl_entry *entry = aim_zmalloc(sizeof(*entry));
    struct vlan_acl_key key;
    struct vlan_acl_key mask;

    rv = parse_key(obj, &key, &mask);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    rv = parse_value(obj, &entry->value);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create vlan_acl entry vlan_vid=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} -> l3_interface_class_id=%u l3_src_class_id=%u vrf=%u",
                    key.vlan_vid, mask.vlan_vid, &key.eth_src, &mask.eth_src, &key.eth_dst, &mask.eth_dst,
                    entry->value.l3_interface_class_id, entry->value.l3_src_class_id, entry->value.vrf);

    tcam_insert(vlan_acl_tcam, &entry->tcam_entry, &key, &mask, 0);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_acl_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct vlan_acl_entry *entry = entry_priv;
    struct vlan_acl_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_acl_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct vlan_acl_entry *entry = entry_priv;

    tcam_remove(vlan_acl_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_acl_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_vlan_acl_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_vlan_acl_entry_create,
    .entry_modify = pipeline_bvs_table_vlan_acl_entry_modify,
    .entry_delete = pipeline_bvs_table_vlan_acl_entry_delete,
    .entry_stats_get = pipeline_bvs_table_vlan_acl_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_vlan_acl_entry_hit_status_get,
};

void
pipeline_bvs_table_vlan_acl_register(void)
{
    vlan_acl_tcam = tcam_create(sizeof(struct vlan_acl_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_VLAN_ACL, "vlan_acl", &table_ops, NULL);
}

void
pipeline_bvs_table_vlan_acl_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_VLAN_ACL);
    tcam_destroy(vlan_acl_tcam);
}

struct vlan_acl_entry *
pipeline_bvs_table_vlan_acl_lookup(const struct vlan_acl_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(vlan_acl_tcam, key);
    if (tcam_entry) {
        struct vlan_acl_entry *entry = container_of(tcam_entry, tcam_entry, struct vlan_acl_entry);
        const struct vlan_acl_key *entry_key = tcam_entry->key;
        const struct vlan_acl_key *entry_mask = tcam_entry->mask;
        packet_trace("Hit vlan_acl entry vlan_vid=%u/%#x eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} -> l3_interface_class_id=%u l3_src_class_id=%u vrf=%u",
                     entry_key->vlan_vid, entry_mask->vlan_vid, &entry_key->eth_src, &entry_mask->eth_src, &entry_key->eth_dst, &entry_mask->eth_dst,
                     entry->value.l3_interface_class_id, entry->value.l3_src_class_id, entry->value.vrf);
        return entry;
    } else {
        packet_trace("Miss vlan_acl entry vlan_vid=%u eth_src=%{mac} eth_dst=%{mac}",
                     key->vlan_vid, &key->eth_src, &key->eth_dst);
        return NULL;
    }
}
