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

#include "pipeline_bvs_int.h"

#define TEMPLATE_NAME arp_offload_hashtable
#define TEMPLATE_OBJ_TYPE struct arp_offload_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *arp_offload_table;
static const indigo_core_gentable_ops_t arp_offload_ops;
static bighash_table_t *arp_offload_hashtable;

void
pipeline_bvs_table_arp_offload_register(void)
{
    arp_offload_hashtable = bighash_table_create(1024);
    indigo_core_gentable_register("arp_offload", &arp_offload_ops, NULL, 1024, 256,
                                  &arp_offload_table);
}

void
pipeline_bvs_table_arp_offload_unregister(void)
{
    indigo_core_gentable_unregister(arp_offload_table);
    bighash_table_destroy(arp_offload_hashtable, NULL);
}

/* arp_offload table operations */

static indigo_error_t
arp_offload_parse_key(of_list_bsn_tlv_t *tlvs, struct arp_offload_key *key)
{
    of_object_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, &key->vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv, &key->ipv4);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_offload_parse_value(of_list_bsn_tlv_t *tlvs)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected empty value list");
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_offload_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct arp_offload_key key;
    struct arp_offload_entry *entry;

    rv = arp_offload_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = arp_offload_parse_value(value_tlvs);
    if (rv < 0) {
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;

    arp_offload_hashtable_insert(arp_offload_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_offload_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;

    rv = arp_offload_parse_value(value_tlvs);
    if (rv < 0) {
        return rv;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_offload_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct arp_offload_entry *entry = entry_priv;
    bighash_remove(arp_offload_hashtable, &entry->hash_entry);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
arp_offload_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do */
}

static const indigo_core_gentable_ops_t arp_offload_ops = {
    .add2 = arp_offload_add,
    .modify2 = arp_offload_modify,
    .del2 = arp_offload_delete,
    .get_stats = arp_offload_get_stats,
};


/* Hashtable lookup */

struct arp_offload_entry *
pipeline_bvs_table_arp_offload_lookup(uint16_t vlan_vid, uint32_t ipv4)
{
    struct arp_offload_key key;
    key.vlan_vid = vlan_vid;
    key.pad = 0;
    key.ipv4 = ipv4;
    struct arp_offload_entry *entry = arp_offload_hashtable_first(arp_offload_hashtable, &key);
    AIM_LOG_VERBOSE("%s arp_offload entry vlan=%u, ip=%{ipv4a}", entry ? "Hit" : "Miss", vlan_vid, ipv4);
    return entry;
}
