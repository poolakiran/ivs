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

static indigo_error_t
parse_value(of_list_bucket_t *of_buckets, struct lag_value *value)
{
    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);
    value->num_buckets = 0;

    of_bucket_t of_bucket;
    int rv;
    OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) {
        struct lag_bucket *bucket =
            xbuf_reserve(&buckets_xbuf, sizeof(*bucket));
        bool seen_port = false;

        of_list_action_t of_actions;
        of_bucket_actions_bind(&of_bucket, &of_actions);

        int rv;
        of_object_t act;
        OF_LIST_ACTION_ITER(&of_actions, &act, rv) {
            switch (act.object_id) {
            case OF_ACTION_OUTPUT:
                if (!seen_port) {
                    of_action_output_port_get(&act, &bucket->port_no);
                    seen_port = true;
                } else {
                    AIM_LOG_ERROR("duplicate output action in LAG group");
                    goto error;
                }
                break;
            case OF_ACTION_BSN_CHECKSUM:
                /* ignore */
                break;
            default:
                AIM_LOG_ERROR("unsupported LAG group action %s", of_object_id_str[act.object_id]);
                goto error;
            }
        }

        if (!seen_port) {
            AIM_LOG_ERROR("missing required action in LAG group");
            goto error;
        }

        value->num_buckets++;
    }

    xbuf_compact(&buckets_xbuf);
    value->buckets = xbuf_steal(&buckets_xbuf);

    return INDIGO_ERROR_NONE;

error:
    xbuf_cleanup(&buckets_xbuf);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct lag_value *value)
{
    aim_free(value->buckets);
}

static indigo_error_t
pipeline_bvs_group_lag_create(
    void *table_priv, indigo_cxn_id_t cxn_id,
    uint32_t group_id, uint8_t group_type, of_list_bucket_t *buckets,
    void **entry_priv)
{
    struct lag_value value;

    if (group_type != OF_GROUP_TYPE_SELECT) {
        AIM_LOG_ERROR("unexpected LAG group type");
        return INDIGO_ERROR_COMPAT;
    }

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    struct lag_group *lag = aim_zmalloc(sizeof(*lag));

    lag->id = group_id;
    lag->value = value;

    if (aim_log_fid_get(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE)) {
        AIM_LOG_VERBOSE("Creating LAG group %d", lag->id);
        int i;
        for (i = 0; i < lag->value.num_buckets; i++) {
            struct lag_bucket *bucket = &lag->value.buckets[i];
            AIM_LOG_VERBOSE("  bucket %d: port %u", i, bucket->port_no);
        }
    }

    *entry_priv = lag;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_lag_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_list_bucket_t *buckets)
{
    struct lag_group *lag = entry_priv;
    struct lag_value value;

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&lag->value);
    lag->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_lag_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv)
{
    struct lag_group *lag = entry_priv;
    cleanup_value(&lag->value);
    aim_free(lag);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_lag_stats_get(
    void *table_priv, void *entry_priv,
    of_group_stats_entry_t *stats)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_group_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_group_lag_create,
    .entry_modify = pipeline_bvs_group_lag_modify,
    .entry_delete = pipeline_bvs_group_lag_delete,
    .entry_stats_get = pipeline_bvs_group_lag_stats_get,
};

void
pipeline_bvs_group_lag_register(void)
{
    indigo_core_group_table_register(GROUP_TABLE_ID_LAG, "lag", &table_ops, NULL);
}

void
pipeline_bvs_group_lag_unregister(void)
{
    indigo_core_group_table_unregister(GROUP_TABLE_ID_LAG);
}

/* Caller must handle NULL return value in case of an empty group */
struct lag_bucket *
pipeline_bvs_group_lag_select(struct lag_group *lag, uint32_t hash)
{
    AIM_ASSERT(lag != NULL);

    if (lag->value.num_buckets == 0) {
        return NULL;
    }

    return &lag->value.buckets[hash % lag->value.num_buckets];
}

struct lag_group *
pipeline_bvs_group_lag_acquire(uint32_t lag_id)
{
    if (group_to_table_id(lag_id) != GROUP_TABLE_ID_LAG) {
        return NULL;
    }

    return indigo_core_group_acquire(lag_id);
}

void
pipeline_bvs_group_lag_release(struct lag_group *lag)
{
    indigo_core_group_release(lag->id);
}

struct lag_group *
pipeline_bvs_group_lag_lookup(uint32_t lag_id)
{
    if (group_to_table_id(lag_id) != GROUP_TABLE_ID_LAG) {
        return NULL;
    }

    return indigo_core_group_lookup(lag_id);
}
