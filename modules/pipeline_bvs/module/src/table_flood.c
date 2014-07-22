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

#define TEMPLATE_NAME flood_hashtable
#define TEMPLATE_OBJ_TYPE struct flood_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static bighash_table_t *flood_hashtable;
static struct flood_entry *miss_entry;
static const of_match_fields_t required_mask = {
    .bsn_lag_id = 0xffffffff,
};
static const of_match_fields_t required_miss_mask = {
    .bsn_lag_id = 0,
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct flood_key *key)
{
    of_match_t match;
    uint16_t priority;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }
    of_flow_add_priority_get(obj, &priority);

    if (priority == 1) {
        if (memcmp(&match.masks, &required_mask, sizeof(of_match_fields_t))) {
            return INDIGO_ERROR_BAD_MATCH;
        }
        key->lag_id = match.fields.bsn_lag_id;
        if (key->lag_id == OF_GROUP_ANY) {
            return INDIGO_ERROR_BAD_MATCH;
        }
    } else if (priority == 0) {
        if (memcmp(&match.masks, &required_miss_mask, sizeof(of_match_fields_t))) {
            return INDIGO_ERROR_BAD_MATCH;
        }
        key->lag_id = OF_GROUP_ANY;
    } else {
        return INDIGO_ERROR_COMPAT;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_flow_add_t *obj, struct flood_value *value)
{
    int rv;
    of_list_instruction_t insts;
    of_instruction_t inst;
    struct xbuf lags_xbuf;

    xbuf_init(&lags_xbuf);
    value->num_lags = 0;

    of_flow_add_instructions_bind(obj, &insts);
    OF_LIST_INSTRUCTION_ITER(&insts, &inst, rv) {
        switch (inst.header.object_id) {
        case OF_INSTRUCTION_APPLY_ACTIONS: {
            of_list_action_t actions;
            of_instruction_apply_actions_actions_bind(&inst.apply_actions, &actions);
            of_action_t act;
            int rv;
            OF_LIST_ACTION_ITER(&actions, &act, rv) {
                switch (act.header.object_id) {
                case OF_ACTION_GROUP: {
                    uint32_t lag_id;
                    of_action_group_group_id_get(&act.group, &lag_id);
                    struct lag_group *lag = pipeline_bvs_group_lag_lookup(lag_id);
                    xbuf_append_ptr(&lags_xbuf, lag);
                    value->num_lags++;
                    break;
                }
                default:
                    AIM_LOG_ERROR("Unexpected action %s in flood table", of_object_id_str[act.header.object_id]);
                    goto error;
                }
            }
            break;
        }
        default:
            AIM_LOG_ERROR("Unexpected instruction %s in flood table", of_object_id_str[inst.header.object_id]);
            goto error;
        }
    }

    xbuf_compact(&lags_xbuf);
    value->lags = xbuf_steal(&lags_xbuf);

    /* Second pass to actually increment the refcounts */
    int i;
    for (i = 0; i < value->num_lags; i++) {
        struct lag_group *lag = value->lags[i];
        AIM_TRUE_OR_DIE(pipeline_bvs_group_lag_acquire(lag->id) == lag);
    }

    return INDIGO_ERROR_NONE;

error:
    xbuf_cleanup(&lags_xbuf);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct flood_value *value)
{
    int i;
    for (i = 0; i < value->num_lags; i++) {
        pipeline_bvs_group_lag_release(value->lags[i]);
    }
    aim_free(value->lags);
}

static indigo_error_t
pipeline_bvs_table_flood_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct flood_entry *entry = aim_zmalloc(sizeof(*entry));

    rv = parse_key(obj, &entry->key);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    rv = parse_value(obj, &entry->value);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create flood entry lag_id=%u", entry->key.lag_id);

    ind_ovs_fwd_write_lock();
    if (entry->key.lag_id == OF_GROUP_ANY) {
        AIM_ASSERT(miss_entry == NULL);
        miss_entry = entry;
    } else {
        flood_hashtable_insert(flood_hashtable, entry);
    }
    ind_ovs_fwd_write_unlock();

    *entry_priv = entry;
    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_flood_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    indigo_error_t rv;
    struct flood_entry *entry = entry_priv;
    struct flood_value value;

    rv = parse_value(obj, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&entry->value);
    entry->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_flood_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct flood_entry *entry = entry_priv;

    ind_ovs_fwd_write_lock();
    if (entry == miss_entry) {
        miss_entry = NULL;
    } else {
        bighash_remove(flood_hashtable, &entry->hash_entry);
    }
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    cleanup_value(&entry->value);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_flood_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_flood_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_flood_entry_create,
    .entry_modify = pipeline_bvs_table_flood_entry_modify,
    .entry_delete = pipeline_bvs_table_flood_entry_delete,
    .entry_stats_get = pipeline_bvs_table_flood_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_flood_entry_hit_status_get,
};

void
pipeline_bvs_table_flood_register(void)
{
    flood_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_table_register(TABLE_ID_FLOOD, "flood", &table_ops, NULL);
}

void
pipeline_bvs_table_flood_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_FLOOD);
    bighash_table_destroy(flood_hashtable, NULL);
}

struct flood_entry *
pipeline_bvs_table_flood_lookup(const struct flood_key *key)
{
    struct flood_entry *entry = flood_hashtable_first(flood_hashtable, key);
    if (entry) {
        AIM_LOG_VERBOSE("Hit flood entry lag_id=%u", entry->key.lag_id);
        return entry;
    } else {
        AIM_LOG_VERBOSE("Miss flood entry lag_id=%u", key->lag_id);
        return miss_entry;
    }
}
