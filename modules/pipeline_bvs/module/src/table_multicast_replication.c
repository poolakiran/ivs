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

static indigo_core_gentable_t *multicast_replication_table;
static const indigo_core_gentable_ops_t multicast_replication_ops;

static void cleanup_key(struct multicast_replication_key *key);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct multicast_replication_key *key)
{
    of_object_t tlv;
    memset(key, 0, sizeof(*key));
    key->vlan_vid = VLAN_INVALID;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t refkey;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &refkey);
        if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
            key->multicast_replication_group = pipeline_bvs_table_multicast_replication_group_acquire(&refkey);
            if (key->multicast_replication_group == NULL) {
                AIM_LOG_ERROR("Nonexistent multicast_replication_group in multicast_replication table");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in multicast_replication table");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference key TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference key TLV, instead got end of list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t refkey;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &refkey);
        if (table_id == pipeline_bvs_table_lag_id) {
            key->lag = pipeline_bvs_table_lag_acquire(&refkey);
            if (key->lag == NULL) {
                AIM_LOG_ERROR("Nonexistent LAG in multicast_replication table");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in multicast_replication table");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference key TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        /* vlan_vid TLV is optional */
        return INDIGO_ERROR_NONE;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, &key->vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan_vid key TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_key(key);
    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct multicast_replication_value *value, uint16_t vlan_vid)
{
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (vlan_vid == VLAN_INVALID) {
        if (of_list_bsn_tlv_first(tlvs, &tlv) == 0) {
            AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
            return INDIGO_ERROR_NONE;
        }
    } else {
        if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
            AIM_LOG_ERROR("expected eth_src value TLV, instead got end of list");
            return INDIGO_ERROR_PARAM;
        }

        if (tlv.object_id == OF_BSN_TLV_ETH_SRC) {
            of_bsn_tlv_eth_src_value_get(&tlv, &value->new_eth_src);
        } else {
            AIM_LOG_ERROR("expected eth_src value TLV, instead got %s", of_class_name(&tlv));
            return INDIGO_ERROR_PARAM;
        }

        if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
            AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
            return INDIGO_ERROR_PARAM;
        }
    }

    return INDIGO_ERROR_NONE;
}

static void
cleanup_key(struct multicast_replication_key *key)
{
    if (key->multicast_replication_group) {
        pipeline_bvs_table_multicast_replication_group_release(key->multicast_replication_group);
        key->multicast_replication_group = NULL;
    }

    if (key->lag) {
        pipeline_bvs_table_lag_release(key->lag);
        key->lag = NULL;
    }
}

static indigo_error_t
multicast_replication_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct multicast_replication_key key;
    struct multicast_replication_value value;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &value, key.vlan_vid)) < 0) {
        return rv;
    }

    struct multicast_replication_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;
    entry->l3 = key.vlan_vid != VLAN_INVALID;

    list_push(&entry->key.multicast_replication_group->members, &entry->links);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_replication_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct multicast_replication_value new_value;
    struct multicast_replication_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value, entry->key.vlan_vid)) < 0) {
        return rv;
    }

    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_replication_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct multicast_replication_entry *entry = entry_priv;
    list_remove(&entry->links);
    cleanup_key(&entry->key);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
multicast_replication_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t multicast_replication_ops = {
    .add2 = multicast_replication_add,
    .modify2 = multicast_replication_modify,
    .del2 = multicast_replication_delete,
    .get_stats = multicast_replication_get_stats,
};

void
pipeline_bvs_table_multicast_replication_register(void)
{
    indigo_core_gentable_register("multicast_replication", &multicast_replication_ops, NULL, 8192, 8192,
                                  &multicast_replication_table);
}

void
pipeline_bvs_table_multicast_replication_unregister(void)
{
    indigo_core_gentable_unregister(multicast_replication_table);
}
