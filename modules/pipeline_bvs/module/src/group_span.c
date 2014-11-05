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
parse_value(of_list_bucket_t *of_buckets, struct span_value *value)
{
    bool seen_lag = false;

    int rv;
    of_bucket_t of_bucket;
    OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) {
        of_list_action_t of_actions;
        of_bucket_actions_bind(&of_bucket, &of_actions);

        int rv;
        of_object_t act;
        OF_LIST_ACTION_ITER(&of_actions, &act, rv) {
            switch (act.object_id) {
            case OF_ACTION_GROUP:
                if (!seen_lag) {
                    uint32_t lag_id;
                    of_action_group_group_id_get(&act, &lag_id);
                    value->lag = pipeline_bvs_group_lag_acquire(lag_id);
                    if (value->lag == NULL) {
                        AIM_LOG_ERROR("nonexistent LAG in SPAN group");
                        goto error;
                    }
                    seen_lag = true;
                } else {
                    AIM_LOG_ERROR("duplicate group action in SPAN group");
                    goto error;
                }
                break;
            default:
                AIM_LOG_ERROR("unsupported SPAN group action %s", of_object_id_str[act.object_id]);
                goto error;
            }
        }
    }

    if (!seen_lag) {
        AIM_LOG_ERROR("SPAN group missing group action");
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    if (seen_lag) {
        pipeline_bvs_group_lag_release(value->lag);
    }
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct span_value *value)
{
    pipeline_bvs_group_lag_release(value->lag);
}

static indigo_error_t
pipeline_bvs_group_span_create(
    void *table_priv, indigo_cxn_id_t cxn_id,
    uint32_t group_id, uint8_t group_type, of_list_bucket_t *buckets,
    void **entry_priv)
{
    struct span_value value;

    if (group_type != OF_GROUP_TYPE_INDIRECT) {
        AIM_LOG_WARN("unexpected SPAN group type");
        return INDIGO_ERROR_COMPAT;
    }

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    struct span_group *span = aim_zmalloc(sizeof(*span));

    span->id = group_id;
    span->value = value;

    AIM_LOG_VERBOSE("Creating span group %u lag %u", span->id, span->value.lag->id);

    *entry_priv = span;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_span_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_list_bucket_t *buckets)
{
    struct span_group *span = entry_priv;
    struct span_value value;

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&span->value);
    span->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_span_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv)
{
    struct span_group *span = entry_priv;
    cleanup_value(&span->value);
    aim_free(span);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_span_stats_get(
    void *table_priv, void *entry_priv,
    of_group_stats_entry_t *stats)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_group_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_group_span_create,
    .entry_modify = pipeline_bvs_group_span_modify,
    .entry_delete = pipeline_bvs_group_span_delete,
    .entry_stats_get = pipeline_bvs_group_span_stats_get,
};

void
pipeline_bvs_group_span_register(void)
{
    indigo_core_group_table_register(GROUP_TABLE_ID_SPAN, "span", &table_ops, NULL);
}

void
pipeline_bvs_group_span_unregister(void)
{
    indigo_core_group_table_unregister(GROUP_TABLE_ID_SPAN);
}

struct span_group *
pipeline_bvs_group_span_acquire(uint32_t span_id)
{
    if (group_to_table_id(span_id) != GROUP_TABLE_ID_SPAN) {
        return NULL;
    }

    return indigo_core_group_acquire(span_id);
}

void
pipeline_bvs_group_span_release(struct span_group *span)
{
    indigo_core_group_release(span->id);
}
