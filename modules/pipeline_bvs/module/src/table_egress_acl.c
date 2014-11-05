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

static struct tcam *egress_acl_tcam;
static const of_match_fields_t maximum_mask = {
    .vlan_vid = 0xffff,
    .bsn_egr_port_group_id = 0xffffffff,
    .bsn_l3_interface_class_id = 0xffffffff,
};
static const of_match_fields_t minimum_mask = {
    .vlan_vid = 0xffff,
    .bsn_egr_port_group_id = 0xffffffff,
    .bsn_l3_interface_class_id = 0,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct egress_acl_key *key, struct egress_acl_key *mask)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    key->vlan_vid = match.fields.vlan_vid & ~VLAN_CFI_BIT;
    mask->vlan_vid = 0xfff;

    if (match.fields.bsn_egr_port_group_id & ~0xff) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    key->egr_port_group_id = match.fields.bsn_egr_port_group_id;
    mask->egr_port_group_id = 0xff;

    if (match.fields.bsn_l3_interface_class_id & ~0xfff) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    key->l3_interface_class_id = match.fields.bsn_l3_interface_class_id;
    mask->l3_interface_class_id = match.masks.bsn_l3_interface_class_id;

    uint16_t priority;
    of_flow_add_priority_get(obj, &priority);
    if (priority != 0) {
        return INDIGO_ERROR_COMPAT;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct egress_acl_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_object_t inst;

    value->drop = false;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.object_id) {
        case OF_INSTRUCTION_BSN_DENY:
            value->drop = true;
            break;
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in egress_acl table", of_object_id_str[inst.object_id]);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_BAD_ACTION;
}

static indigo_error_t
pipeline_bvs_table_egress_acl_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct egress_acl_entry *entry = aim_zmalloc(sizeof(*entry));
    struct egress_acl_key key;
    struct egress_acl_key mask;

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

    AIM_LOG_VERBOSE("Create egress_acl entry vlan_vid=%u l3_interface_class_id=%u/%#x egr_port_group_id=%u drop=%u",
                    key.vlan_vid, key.l3_interface_class_id, mask.l3_interface_class_id, key.egr_port_group_id, entry->value.drop);

    ind_ovs_fwd_write_lock();
    tcam_insert(egress_acl_tcam, &entry->tcam_entry, &key, &mask, 0);
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_acl_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct egress_acl_entry *entry = entry_priv;
    struct egress_acl_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_acl_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct egress_acl_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    tcam_remove(egress_acl_tcam, &entry->tcam_entry);
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_acl_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_egress_acl_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_egress_acl_entry_create,
    .entry_modify = pipeline_bvs_table_egress_acl_entry_modify,
    .entry_delete = pipeline_bvs_table_egress_acl_entry_delete,
    .entry_stats_get = pipeline_bvs_table_egress_acl_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_egress_acl_entry_hit_status_get,
};

void
pipeline_bvs_table_egress_acl_register(void)
{
    egress_acl_tcam = tcam_create(sizeof(struct egress_acl_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_EGRESS_ACL, "egress_acl", &table_ops, NULL);
}

void
pipeline_bvs_table_egress_acl_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_EGRESS_ACL);
    tcam_destroy(egress_acl_tcam);
}

struct egress_acl_entry *
pipeline_bvs_table_egress_acl_lookup(const struct egress_acl_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(egress_acl_tcam, key);
    if (tcam_entry) {
        struct egress_acl_entry *entry = container_of(tcam_entry, tcam_entry, struct egress_acl_entry);
        const struct egress_acl_key *entry_key = tcam_entry->key;
        const struct egress_acl_key *entry_mask = tcam_entry->mask;
        AIM_LOG_VERBOSE("Hit egress_acl entry vlan_vid=%u l3_interface_class_id=%u/%#x egr_port_group_id=%u drop=%u",
                        entry_key->vlan_vid, entry_key->l3_interface_class_id,
                        entry_mask->l3_interface_class_id, entry_key->egr_port_group_id,
                        entry->value.drop);
        return entry;
    } else {
        AIM_LOG_VERBOSE("Miss egress_acl entry vlan_vid=%u l3_interface_class_id=%u egr_port_group_id=%u",
                        key->vlan_vid, key->l3_interface_class_id, key->egr_port_group_id);
        return NULL;
    }
}
