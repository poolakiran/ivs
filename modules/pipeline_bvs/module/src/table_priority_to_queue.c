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

static indigo_core_gentable_t *priority_to_queue_table;
static const indigo_core_gentable_ops_t priority_to_queue_ops;
static LIST_DEFINE(priority_to_queue_list);

static indigo_error_t
priority_to_queue_parse_key(of_list_bsn_tlv_t *tlvs,
                            struct priority_to_queue_key *key)
{
    of_object_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_PRIORITY) {
        of_bsn_tlv_priority_value_get(&tlv, &key->internal_priority);
    } else {
        AIM_LOG_ERROR("expected priority key TLV, instead got %s",
                      of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s",
                      of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
priority_to_queue_parse_value(of_list_bsn_tlv_t *tlvs,
                              struct priority_to_queue_value *value)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_QUEUE_ID) {
        of_bsn_tlv_queue_id_value_get(&tlv, &value->queue_id);
    } else {
        AIM_LOG_ERROR("expected queue_id value TLV, instead got %s",
                      of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s",
                      of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
priority_to_queue_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs,
                      of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct priority_to_queue_key key;
    struct priority_to_queue_value value;
    struct priority_to_queue_entry *entry;

    rv = priority_to_queue_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = priority_to_queue_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    AIM_LOG_TRACE("Create priority_to_queue entry prio=%u -> queue_id=%u",
                  entry->key.internal_priority, entry->value.queue_id);
    list_push(&priority_to_queue_list, &entry->links);

    *entry_priv = entry;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
priority_to_queue_modify(void *table_priv, void *entry_priv,
                         of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct priority_to_queue_value value;
    struct priority_to_queue_entry *entry = entry_priv;

    rv = priority_to_queue_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    AIM_LOG_TRACE("Modify priority_to_queue entry prio=%u from queue_id=%u to "
                  "queue_id=%u", entry->key.internal_priority,
                  entry->value.queue_id, value.queue_id);
    entry->value = value;

    return INDIGO_ERROR_NONE;
}


static indigo_error_t
priority_to_queue_delete(void *table_priv, void *entry_priv,
                         of_list_bsn_tlv_t *key_tlvs)
{
    struct priority_to_queue_entry *entry = entry_priv;
    AIM_LOG_TRACE("Delete priority_to_queue entry prio=%u -> queue_id=%u",
                  entry->key.internal_priority, entry->value.queue_id);
    list_remove(&entry->links);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static void
priority_to_queue_get_stats(void *table_priv, void *entry_priv,
                            of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t priority_to_queue_ops = {
    .add = priority_to_queue_add,
    .modify = priority_to_queue_modify,
    .del = priority_to_queue_delete,
    .get_stats = priority_to_queue_get_stats,
};

void
pipeline_bvs_table_priority_to_queue_register(void)
{
    indigo_core_gentable_register("priority_to_queue", &priority_to_queue_ops, NULL, 12, 8,
                                  &priority_to_queue_table);
}

void
pipeline_bvs_table_priority_to_queue_unregister(void)
{
    indigo_core_gentable_unregister(priority_to_queue_table);
}

struct priority_to_queue_entry *
pipeline_bvs_table_priority_to_queue_lookup(uint32_t internal_priority)
{
    list_links_t *cur;
    LIST_FOREACH(&priority_to_queue_list, cur) {
        struct priority_to_queue_entry *entry = container_of(cur, links,
                                                             struct priority_to_queue_entry);
        if (entry->key.internal_priority == internal_priority) {
            AIM_LOG_VERBOSE("Hit priority_to_queue entry prio=%u, queue_id=%u",
                            internal_priority, entry->value.queue_id);
            return entry;
        }
    }

    AIM_LOG_VERBOSE("Miss priority_to_queue entry prio=%u", internal_priority);
    return NULL;
}
