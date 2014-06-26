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
parse_value(of_list_bucket_t *of_buckets, struct ecmp_value *value)
{
    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);
    value->num_buckets = 0;

    of_bucket_t of_bucket;
    int rv;
    OF_LIST_BUCKET_ITER(of_buckets, &of_bucket, rv) {
        struct ecmp_bucket *bucket =
            xbuf_reserve(&buckets_xbuf, sizeof(*bucket));

        of_list_action_t actions;
        of_bucket_actions_bind(&of_bucket, &actions);

        if (pipeline_bvs_parse_next_hop(&actions, &bucket->next_hop) < 0) {
            AIM_LOG_ERROR("Failed to parse next-hop in ECMP group");
            goto error;
        }

        value->num_buckets++;

        of_action_t act;
        int rv;
        OF_LIST_ACTION_ITER(&actions, &act, rv) {
            switch (act.header.object_id) {
            case OF_ACTION_GROUP:
                /* Handled by pipeline_bvs_parse_next_hop */
                break;
            case OF_ACTION_SET_FIELD: {
                of_oxm_t oxm;
                of_action_set_field_field_bind(&act.set_field, &oxm.header);
                switch (oxm.header.object_id) {
                case OF_OXM_VLAN_VID:
                case OF_OXM_ETH_SRC:
                case OF_OXM_ETH_DST:
                    /* Handled by pipeline_bvs_parse_next_hop */
                    break;
                default:
                    AIM_LOG_ERROR("Unexpected set-field OXM %s in ECMP group", of_object_id_str[oxm.header.object_id]);
                    goto error;
                }
                break;
            }
            default:
                AIM_LOG_ERROR("Unexpected action %s in ECMP group", of_object_id_str[act.header.object_id]);
                goto error;
            }
        }

        if (bucket->next_hop.type != NEXT_HOP_TYPE_LAG) {
            AIM_LOG_ERROR("Invalid ECMP group next-hop type");
            goto error;
        }
    }

    xbuf_compact(&buckets_xbuf);
    value->buckets = xbuf_steal(&buckets_xbuf);

    return INDIGO_ERROR_NONE;

error:
    {
        int i;
        struct ecmp_bucket *buckets = xbuf_data(&buckets_xbuf);
        for (i = 0; i < value->num_buckets; i++) {
            pipeline_bvs_cleanup_next_hop(&buckets[i].next_hop);
        }
    }

    xbuf_cleanup(&buckets_xbuf);
    return INDIGO_ERROR_COMPAT;
}

static void
cleanup_value(struct ecmp_value *value)
{
    int i;
    for (i = 0; i < value->num_buckets; i++) {
        pipeline_bvs_cleanup_next_hop(&value->buckets[i].next_hop);
    }
    aim_free(value->buckets);
}

static indigo_error_t
pipeline_bvs_group_ecmp_create(
    void *table_priv, indigo_cxn_id_t cxn_id,
    uint32_t group_id, uint8_t group_type, of_list_bucket_t *buckets,
    void **entry_priv)
{
    struct ecmp_value value;

    if (group_type != OF_GROUP_TYPE_SELECT) {
        AIM_LOG_WARN("unexpected ECMP group type");
        return INDIGO_ERROR_COMPAT;
    }

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    struct ecmp_group *ecmp = aim_zmalloc(sizeof(*ecmp));

    ecmp->id = group_id;
    ecmp->value = value;

    if (aim_log_fid_get(AIM_LOG_STRUCT_POINTER, AIM_LOG_FLAG_VERBOSE)) {
        AIM_LOG_VERBOSE("Create ECMP group %d", ecmp->id);
        int i;
        for (i = 0; i < ecmp->value.num_buckets; i++) {
            struct ecmp_bucket *bucket = &ecmp->value.buckets[i];
            AIM_LOG_VERBOSE("  bucket %d: next_hop=%{mac}", i, &bucket->next_hop);
        }
    }

    *entry_priv = ecmp;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_ecmp_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_list_bucket_t *buckets)
{
    struct ecmp_group *ecmp = entry_priv;
    struct ecmp_value value;

    indigo_error_t rv = parse_value(buckets, &value);
    if (rv < 0) {
        return rv;
    }

    ind_ovs_fwd_write_lock();
    cleanup_value(&ecmp->value);
    ecmp->value = value;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_ecmp_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv)
{
    struct ecmp_group *ecmp = entry_priv;
    cleanup_value(&ecmp->value);
    aim_free(ecmp);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_group_ecmp_stats_get(
    void *table_priv, void *entry_priv,
    of_group_stats_entry_t *stats)
{
    return INDIGO_ERROR_NONE;
}

static const indigo_core_group_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_group_ecmp_create,
    .entry_modify = pipeline_bvs_group_ecmp_modify,
    .entry_delete = pipeline_bvs_group_ecmp_delete,
    .entry_stats_get = pipeline_bvs_group_ecmp_stats_get,
};

void
pipeline_bvs_group_ecmp_register(void)
{
    indigo_core_group_table_register(GROUP_TABLE_ID_ECMP, "ecmp", &table_ops, NULL);
}

void
pipeline_bvs_group_ecmp_unregister(void)
{
    indigo_core_group_table_unregister(GROUP_TABLE_ID_ECMP);
}

struct ecmp_bucket *
pipeline_bvs_group_ecmp_select(struct ecmp_group *ecmp, uint32_t hash)
{
    AIM_ASSERT(ecmp != NULL);

    if (ecmp->value.num_buckets == 0) {
        return NULL;
    }

    return &ecmp->value.buckets[hash % ecmp->value.num_buckets];
}

struct ecmp_group *
pipeline_bvs_group_ecmp_acquire(uint32_t ecmp_id)
{
    if (group_to_table_id(ecmp_id) != GROUP_TABLE_ID_ECMP) {
        return NULL;
    }

    return indigo_core_group_acquire(ecmp_id);
}

void
pipeline_bvs_group_ecmp_release(struct ecmp_group *ecmp)
{
    indigo_core_group_release(ecmp->id);
}
