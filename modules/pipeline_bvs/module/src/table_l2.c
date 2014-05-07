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
pipeline_bvs_table_l2_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    *entry_priv = NULL;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static indigo_error_t
pipeline_bvs_table_l2_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_l2_entry_create,
    .entry_modify = pipeline_bvs_table_l2_entry_modify,
    .entry_delete = pipeline_bvs_table_l2_entry_delete,
    .entry_stats_get = pipeline_bvs_table_l2_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_l2_entry_hit_status_get,
};

void
pipeline_bvs_table_l2_register(void)
{
    indigo_core_table_register(TABLE_ID_L2, "l2", &table_ops, NULL);
}

void
pipeline_bvs_table_l2_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_L2);
}
