/****************************************************************
 *
 *        Copyright 2016, Big Switch Networks, Inc.
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

#define TEMPLATE_NAME vlan_xlate2_hashtable
#define TEMPLATE_OBJ_TYPE struct vlan_xlate2_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static void cleanup_key(struct vlan_xlate2_key *key);

static indigo_core_gentable_t *vlan_xlate2_table;
static const indigo_core_gentable_ops_t vlan_xlate2_ops;
static bighash_table_t *vlan_xlate2_hashtable;

void
pipeline_bvs_table_vlan_xlate2_register(void)
{
    vlan_xlate2_hashtable = bighash_table_create(1024);
    indigo_core_gentable_register("vlan_xlate2", &vlan_xlate2_ops, NULL, 1024, 256,
                                  &vlan_xlate2_table);
}

void
pipeline_bvs_table_vlan_xlate2_unregister(void)
{
    indigo_core_gentable_unregister(vlan_xlate2_table);
    bighash_table_destroy(vlan_xlate2_hashtable, NULL);
}

/* vlan_xlate2 table operations */

static indigo_error_t
vlan_xlate2_parse_key(of_list_bsn_tlv_t *tlvs, struct vlan_xlate2_key *key)
{
    of_object_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, &key->vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of key list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        uint16_t table_id;
        of_object_t ref_key;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &ref_key);
        if (table_id == pipeline_bvs_table_lag_id) {
            key->lag = pipeline_bvs_table_lag_acquire(&ref_key);
            if (key->lag == NULL) {
                AIM_LOG_ERROR("Nonexistent LAG in vlan_xlate table");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("Unexpected gentable id in vlan_xlate table");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.object_id]);
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_key(key);
    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
vlan_xlate2_parse_value(of_list_bsn_tlv_t *tlvs, struct vlan_xlate2_value *value)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, &value->new_vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan_vid value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    /* qos_priority is optional */
    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        return INDIGO_ERROR_NONE;
    }

    if (tlv.object_id == OF_BSN_TLV_QOS_PRIORITY) {
        of_bsn_tlv_qos_priority_value_get(&tlv, &value->internal_priority);
    } else {
        AIM_LOG_ERROR("expected qos_priority value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
vlan_xlate2_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct vlan_xlate2_key key;
    struct vlan_xlate2_value value;
    struct vlan_xlate2_entry *entry;

    rv = vlan_xlate2_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = vlan_xlate2_parse_value(value_tlvs, &value);
    if (rv < 0) {
        cleanup_key(&key);
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    vlan_xlate2_hashtable_insert(vlan_xlate2_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
vlan_xlate2_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct vlan_xlate2_value value;
    struct vlan_xlate2_entry *entry = entry_priv;

    rv = vlan_xlate2_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
vlan_xlate2_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct vlan_xlate2_entry *entry = entry_priv;
    bighash_remove(vlan_xlate2_hashtable, &entry->hash_entry);
    cleanup_key(&entry->key);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
vlan_xlate2_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do */
}

static const indigo_core_gentable_ops_t vlan_xlate2_ops = {
    .add2 = vlan_xlate2_add,
    .modify2 = vlan_xlate2_modify,
    .del2 = vlan_xlate2_delete,
    .get_stats = vlan_xlate2_get_stats,
};


/* Hashtable lookup */

struct vlan_xlate2_entry *
pipeline_bvs_table_vlan_xlate2_lookup(struct lag_group *lag, uint16_t vlan_vid)
{
    struct vlan_xlate2_key key;
    key.lag = lag;
    key.vlan_vid = vlan_vid;
    key.pad = 0;
    key.pad2 = 0;
    struct vlan_xlate2_entry *entry = vlan_xlate2_hashtable_first(vlan_xlate2_hashtable, &key);
    if (entry) {
        packet_trace("Hit vlan_xlate2 entry lag=%s vlan_vid=%u -> new_vlan_vid=%u", lag_name(lag), vlan_vid, entry->value.new_vlan_vid);
    } else {
        packet_trace("Miss vlan_xlate2 entry lag=%s vlan_vid=%u", lag_name(lag), vlan_vid);
    }
    return entry;
}

static void
cleanup_key(struct vlan_xlate2_key *key)
{
    if (key->lag != NULL) {
        pipeline_bvs_table_lag_release(key->lag);
    }
}
