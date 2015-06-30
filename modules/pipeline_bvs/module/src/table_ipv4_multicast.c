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
#include <indigo/of_state_manager.h>
#include "pipeline_bvs_int.h"

#define TEMPLATE_NAME ipv4_multicast_hashtable
#define TEMPLATE_OBJ_TYPE struct ipv4_multicast_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *ipv4_multicast_table;
static const indigo_core_gentable_ops_t ipv4_multicast_ops;
static bighash_table_t *ipv4_multicast_hashtable;

static void cleanup_value(struct ipv4_multicast_value *value);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct ipv4_multicast_key *key)
{
    of_object_t tlv;
    memset(key, 0, sizeof(*key));

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

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected vrf key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VRF) {
        of_bsn_tlv_vrf_value_get(&tlv, &key->vrf);
    } else {
        AIM_LOG_ERROR("expected vrf key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv, &key->ipv4);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct ipv4_multicast_value *value)
{
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference value TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t refkey;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &refkey);
        if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
            value->multicast_replication_group = pipeline_bvs_table_multicast_replication_group_acquire(&refkey);
            if (value->multicast_replication_group == NULL) {
                AIM_LOG_ERROR("Nonexistent multicast_replication_group in multicast_replication multicast_replication table");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in multicast_replication table");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference value TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct ipv4_multicast_value *value)
{
    if (value->multicast_replication_group) {
        pipeline_bvs_table_multicast_replication_group_release(value->multicast_replication_group);
        value->multicast_replication_group = NULL;
    }
}

static indigo_error_t
ipv4_multicast_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct ipv4_multicast_key key;
    struct ipv4_multicast_value value;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &value)) < 0) {
        return rv;
    }

    struct ipv4_multicast_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    ipv4_multicast_hashtable_insert(ipv4_multicast_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ipv4_multicast_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct ipv4_multicast_value new_value;
    struct ipv4_multicast_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ipv4_multicast_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct ipv4_multicast_entry *entry = entry_priv;
    bighash_remove(ipv4_multicast_hashtable, &entry->hash_entry);
    cleanup_value(&entry->value);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
ipv4_multicast_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t ipv4_multicast_ops = {
    .add2 = ipv4_multicast_add,
    .modify2 = ipv4_multicast_modify,
    .del2 = ipv4_multicast_delete,
    .get_stats = ipv4_multicast_get_stats,
};

void
pipeline_bvs_table_ipv4_multicast_register(void)
{
    ipv4_multicast_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_gentable_register("ipv4_multicast", &ipv4_multicast_ops, NULL, 128, 128,
                                  &ipv4_multicast_table);
}

void
pipeline_bvs_table_ipv4_multicast_unregister(void)
{
    indigo_core_gentable_unregister(ipv4_multicast_table);
    bighash_table_destroy(ipv4_multicast_hashtable, NULL);
}

struct ipv4_multicast_entry *
pipeline_bvs_table_ipv4_multicast_lookup(uint16_t vlan_vid, uint32_t vrf, uint32_t ipv4)
{
    struct ipv4_multicast_key key = { .vlan_vid = vlan_vid, .pad = 0, .vrf = vrf, .ipv4 = ipv4 };
    return ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
}
