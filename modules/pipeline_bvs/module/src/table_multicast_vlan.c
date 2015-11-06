/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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
#include <indigo/of_state_manager.h>
#include "pipeline_bvs_int.h"

#define TEMPLATE_NAME multicast_vlan_hashtable
#define TEMPLATE_OBJ_TYPE struct multicast_vlan_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *multicast_vlan_table;
static const indigo_core_gentable_ops_t multicast_vlan_ops;
static bighash_table_t *multicast_vlan_hashtable;

static void cleanup_value(struct multicast_vlan_value *value);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct multicast_vlan_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected vlan_vid key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, &key->vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan_vid key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct multicast_vlan_value *value)
{
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        goto end;
    }

    if (tlv.object_id == OF_BSN_TLV_IGMP_SNOOPING) {
        value->igmp_snooping = true;
        if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
            goto end;
        }
    }

    if (tlv.object_id == OF_BSN_TLV_MULTICAST_INTERFACE_ID) {
        of_bsn_tlv_multicast_interface_id_value_get(&tlv, &value->multicast_interface_id);
        if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
            goto end;
        }
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t refkey;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &refkey);
        if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
            value->default_replication_group = pipeline_bvs_table_multicast_replication_group_acquire(&refkey);
            if (value->default_replication_group == NULL) {
                AIM_LOG_ERROR("Nonexistent multicast_replication_group in multicast_vlan table");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in multicast_vlan table");
            goto error;
        }

        if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
            goto end;
        }
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

end:
    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct multicast_vlan_value *value)
{
    if (value->default_replication_group) {
        pipeline_bvs_table_multicast_replication_group_release(value->default_replication_group);
        value->default_replication_group = NULL;
    }
}

static indigo_error_t
multicast_vlan_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct multicast_vlan_key key;
    struct multicast_vlan_value value;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &value)) < 0) {
        return rv;
    }

    struct multicast_vlan_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    multicast_vlan_hashtable_insert(multicast_vlan_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_vlan_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct multicast_vlan_value new_value;
    struct multicast_vlan_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_vlan_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct multicast_vlan_entry *entry = entry_priv;
    bighash_remove(multicast_vlan_hashtable, &entry->hash_entry);
    cleanup_value(&entry->value);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
multicast_vlan_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t multicast_vlan_ops = {
    .add2 = multicast_vlan_add,
    .modify2 = multicast_vlan_modify,
    .del2 = multicast_vlan_delete,
    .get_stats = multicast_vlan_get_stats,
};

void
pipeline_bvs_table_multicast_vlan_register(void)
{
    multicast_vlan_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_gentable_register("multicast_vlan", &multicast_vlan_ops, NULL, 128, 128,
                                  &multicast_vlan_table);
}

void
pipeline_bvs_table_multicast_vlan_unregister(void)
{
    indigo_core_gentable_unregister(multicast_vlan_table);
    bighash_table_destroy(multicast_vlan_hashtable, NULL);
}

struct multicast_vlan_entry *
pipeline_bvs_table_multicast_vlan_lookup(uint16_t vlan_vid)
{
    struct multicast_vlan_key key = { .vlan_vid = vlan_vid };
    struct multicast_vlan_entry *entry =
        multicast_vlan_hashtable_first(multicast_vlan_hashtable, &key);
    if (entry) {
        packet_trace("Hit multicast_vlan entry vlan_vid=%u -> igmp_snooping=%u multicast_interface_id=%u default_replication_group=%s",
                     entry->key.vlan_vid, entry->value.igmp_snooping, entry->value.multicast_interface_id,
                     entry->value.default_replication_group ? entry->value.default_replication_group->key.name : "(none)");
    } else {
        packet_trace("Miss multicast_vlan entry vlan_vid=%u", vlan_vid);
    }
    return entry;
}
