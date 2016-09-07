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

static indigo_core_gentable_t *priority_to_pcp_profile_table;
static const indigo_core_gentable_ops_t priority_to_pcp_profile_ops;
uint16_t pipeline_bvs_table_priority_to_pcp_profile_id;
LIST_DEFINE(pipeline_bvs_table_priority_to_pcp_profile_entries);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct priority_to_pcp_profile_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected name key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_NAME) {
        of_octets_t name;
        of_bsn_tlv_name_value_get(&tlv, &name);
        if (name.bytes >= sizeof(key->name)) {
            AIM_LOG_ERROR("priority_to_pcp_profile name too long");
            return INDIGO_ERROR_PARAM;
        }
        if (strnlen((char *)name.data, name.bytes) != name.bytes) {
            AIM_LOG_ERROR("priority_to_pcp_profile name includes null bytes");
            return INDIGO_ERROR_PARAM;
        }
        memcpy(key->name, name.data, name.bytes);
        key->name[name.bytes] = 0;
    } else {
        AIM_LOG_ERROR("expected name key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_bucket(of_bsn_tlv_bucket_t *bucket, struct priority_to_pcp_profile_value *value)
{
    uint8_t vlan_pcp;
    uint32_t qos_priority;
    of_object_t tlvs, tlv;
    of_bsn_tlv_bucket_value_bind(bucket, &tlvs);

    if (of_list_bsn_tlv_first(&tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected qos_priority TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_QOS_PRIORITY) {
        of_bsn_tlv_qos_priority_value_get(&tlv, &qos_priority);
        if (qos_priority >= NUM_INTERNAL_PRIORITY) {
            AIM_LOG_ERROR("Invalid qos_priority (%u)", qos_priority);
            return INDIGO_ERROR_PARAM;
        }
    } else {
        AIM_LOG_ERROR("expected qos_priority TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(&tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected vlan_pcp TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_PCP) {
        of_bsn_tlv_vlan_pcp_value_get(&tlv, &vlan_pcp);
        if (vlan_pcp >= 8) {
            AIM_LOG_ERROR("Invalid vlan_pcp (%u)", vlan_pcp);
            return INDIGO_ERROR_PARAM;
        }
    } else {
        AIM_LOG_ERROR("expected vlan_pcp TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(&tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    value->buckets[qos_priority].vlan_pcp = vlan_pcp;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct priority_to_pcp_profile_value *value)
{
    int i;
    for (i = 0; i < NUM_INTERNAL_PRIORITY; i++) {
        value->buckets[i].vlan_pcp = 0;
    }

    of_object_t tlv;
    int rv;
    int bucket_count = 0;
    OF_LIST_BSN_TLV_ITER(tlvs, &tlv, rv) {
        if (tlv.object_id == OF_BSN_TLV_BUCKET) {
            if (parse_bucket(&tlv, value) < 0) {
                goto error;
            }
        } else {
            AIM_LOG_ERROR("expected bucket value TLV, instead got %s", of_class_name(&tlv));
            goto error;
        }

        if (++bucket_count > NUM_INTERNAL_PRIORITY) {
            AIM_LOG_ERROR("bucket count %d exceeding internal priority count %d",
                          bucket_count, NUM_INTERNAL_PRIORITY);
            goto error;
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct priority_to_pcp_profile_value *value)
{
}

static indigo_error_t
priority_to_pcp_profile_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct priority_to_pcp_profile_entry *entry = aim_zmalloc(sizeof(*entry));

    if ((rv = parse_key(key, &entry->key)) < 0) {
        aim_free(entry);
        return rv;
    }

    if ((rv = parse_value(value, &entry->value)) < 0) {
        aim_free(entry);
        return rv;
    }

    list_push(&pipeline_bvs_table_priority_to_pcp_profile_entries, &entry->links);

    *entry_priv = entry;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
priority_to_pcp_profile_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    struct priority_to_pcp_profile_value new_value;
    struct priority_to_pcp_profile_entry *entry = entry_priv;

    if ((rv = parse_value(value, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
priority_to_pcp_profile_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct priority_to_pcp_profile_entry *entry = entry_priv;
    list_remove(&entry->links);
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static void
priority_to_pcp_profile_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t priority_to_pcp_profile_ops = {
    .add2 = priority_to_pcp_profile_add,
    .modify2 = priority_to_pcp_profile_modify,
    .del2 = priority_to_pcp_profile_delete,
    .get_stats = priority_to_pcp_profile_get_stats,
};

void
pipeline_bvs_table_priority_to_pcp_profile_register(void)
{
    indigo_core_gentable_register("priority_to_pcp_profile", &priority_to_pcp_profile_ops, NULL, 128, 128,
                                  &priority_to_pcp_profile_table);
    pipeline_bvs_table_priority_to_pcp_profile_id = indigo_core_gentable_id(priority_to_pcp_profile_table);
}

void
pipeline_bvs_table_priority_to_pcp_profile_unregister(void)
{
    indigo_core_gentable_unregister(priority_to_pcp_profile_table);
}

struct priority_to_pcp_profile_entry *
pipeline_bvs_table_priority_to_pcp_profile_acquire(of_object_t *key)
{
    return indigo_core_gentable_acquire(priority_to_pcp_profile_table, key);
}

void
pipeline_bvs_table_priority_to_pcp_profile_release(struct priority_to_pcp_profile_entry *entry)
{
    /* HACK */
    of_object_t *key = of_bsn_tlv_name_new(OF_VERSION_1_3);
    of_octets_t name = { .data = (uint8_t *)entry->key.name, .bytes = strlen(entry->key.name) };
    if (of_bsn_tlv_name_value_set(key, &name) < 0) {
        AIM_DIE("Unexpected error creating priority_to_pcp_profile key in pipeline_bvs_table_priority_to_pcp_profile_release");
    }
    indigo_core_gentable_release(priority_to_pcp_profile_table, key);
    of_object_delete(key);
}

struct priority_to_pcp_profile_entry *
pipeline_bvs_table_priority_to_pcp_profile_lookup(of_object_t *key)
{
    return indigo_core_gentable_lookup(priority_to_pcp_profile_table, key);
}
