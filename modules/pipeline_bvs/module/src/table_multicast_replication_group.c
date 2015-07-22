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

static indigo_core_gentable_t *multicast_replication_group_table;
static const indigo_core_gentable_ops_t multicast_replication_group_ops;
uint16_t pipeline_bvs_table_multicast_replication_group_id;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct multicast_replication_group_key *key)
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
            AIM_LOG_ERROR("multicast_replication_group name too long");
            return INDIGO_ERROR_PARAM;
        }
        if (strnlen((char *)name.data, name.bytes) != name.bytes) {
            AIM_LOG_ERROR("multicast_replication_group name includes null bytes");
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
multicast_replication_group_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct multicast_replication_group_key key;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    struct multicast_replication_group_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    list_init(&entry->members);

    AIM_LOG_VERBOSE("Created multicast replication group \"%.64s\"", key.name);

    *entry_priv = entry;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_replication_group_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
multicast_replication_group_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct multicast_replication_group_entry *entry = entry_priv;
    AIM_ASSERT(list_empty(&entry->members));
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static void
multicast_replication_group_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t multicast_replication_group_ops = {
    .add2 = multicast_replication_group_add,
    .modify2 = multicast_replication_group_modify,
    .del2 = multicast_replication_group_delete,
    .get_stats = multicast_replication_group_get_stats,
};

void
pipeline_bvs_table_multicast_replication_group_register(void)
{
    indigo_core_gentable_register("multicast_replication_group", &multicast_replication_group_ops, NULL, 128, 128,
                                  &multicast_replication_group_table);
    pipeline_bvs_table_multicast_replication_group_id = indigo_core_gentable_id(multicast_replication_group_table);
}

void
pipeline_bvs_table_multicast_replication_group_unregister(void)
{
    indigo_core_gentable_unregister(multicast_replication_group_table);
}

struct multicast_replication_group_entry *
pipeline_bvs_table_multicast_replication_group_acquire(of_object_t *key)
{
    return indigo_core_gentable_acquire(multicast_replication_group_table, key);
}

void
pipeline_bvs_table_multicast_replication_group_release(struct multicast_replication_group_entry *multicast_replication_group)
{
    /* HACK */
    of_object_t *key = of_bsn_tlv_name_new(OF_VERSION_1_3);
    of_octets_t name = { .data = (uint8_t *)multicast_replication_group->key.name, .bytes = strlen(multicast_replication_group->key.name) };
    if (of_bsn_tlv_name_value_set(key, &name) < 0) {
        AIM_DIE("Unexpected error creating multicast_replication_group key in pipeline_bvs_table_multicast_replication_group_release");
    }
    indigo_core_gentable_release(multicast_replication_group_table, key);
    of_object_delete(key);
}

struct multicast_replication_group_entry *
pipeline_bvs_table_multicast_replication_group_lookup(of_object_t *key)
{
    return indigo_core_gentable_lookup(multicast_replication_group_table, key);
}
