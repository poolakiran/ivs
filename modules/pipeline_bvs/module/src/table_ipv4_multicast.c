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

    if (of_list_bsn_tlv_first(tlvs, &tlv) != OF_ERROR_NONE ) {
        AIM_LOG_ERROR("expected multicast_interface_id key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_MULTICAST_INTERFACE_ID) {
        of_bsn_tlv_multicast_interface_id_value_get(&tlv, &key->multicast_interface_id);
    } else {
        AIM_LOG_ERROR("expected multicast_interface_id key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) != OF_ERROR_NONE) {
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
        if (of_list_bsn_tlv_next(tlvs, &tlv) != OF_ERROR_NONE) {
            return INDIGO_ERROR_NONE;
        }
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    /* Optional ipv4_src */
    if (tlv.object_id == OF_BSN_TLV_IPV4_SRC) {
        of_bsn_tlv_ipv4_value_get(&tlv, &key->ipv4_src);
    } else {
        AIM_LOG_ERROR("expected ipv4_src key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == OF_ERROR_NONE) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct ipv4_multicast_value *value)
{
    int rv;
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference value TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    OF_LIST_BSN_TLV_ITER(tlvs, &tlv, rv) {
        switch(tlv.object_id) {
        case OF_BSN_TLV_REFERENCE: {
            of_object_t refkey;
            uint16_t table_id;
            of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
            of_bsn_tlv_reference_key_bind(&tlv, &refkey);
            if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
                value->multicast_replication_group = pipeline_bvs_table_multicast_replication_group_acquire(&refkey);
                if (value->multicast_replication_group == NULL) {
                    AIM_LOG_ERROR("Nonexistent multicast_replication_group in multicast_replication multicast_replication table");
                    cleanup_value(value);
                    return INDIGO_ERROR_PARAM;
                }
            } else {
                AIM_LOG_ERROR("unsupported gentable reference in multicast_replication table");
                cleanup_value(value);
                return INDIGO_ERROR_PARAM;
            }
            break;
        }

        /* ignore below TLVs */
        case OF_BSN_TLV_MULTICAST_INTERFACE_ID: /* fall-through */
        case OF_BSN_TLV_PORT: /* fall-through */
        case OF_BSN_TLV_DROP: /* fall-through */
        default:
            break;
        }
    }

    return INDIGO_ERROR_NONE;
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
pipeline_bvs_table_ipv4_multicast_lookup(uint16_t multicast_interface_id, uint32_t vrf, uint32_t ipv4, uint32_t ipv4_src)
{
    struct ipv4_multicast_key key = { .multicast_interface_id = multicast_interface_id,
                                      .vrf = vrf, .ipv4 = ipv4, .ipv4_src = ipv4_src};
    struct ipv4_multicast_entry *entry = NULL;

    /* (S,G) lookup */
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit (s,g) ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* (*,G) lookup */
    key.ipv4_src = 0;
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit (*,g) ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* default entry lookup */
    AIM_ZERO(key);
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit default ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* Missed multicast lookup */
    packet_trace("Miss ipv4_multicast entry multicast_interface_id=%u"
                 " vrf=%u ipv4=%08x ipv4_src=%08x",
                 entry->key.multicast_interface_id,
                 entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
    return entry;
}
