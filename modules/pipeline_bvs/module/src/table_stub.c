/****************************************************************
 *
 *        Copyright 2017, Big Switch Networks, Inc.
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

/* List of stubbed gentables */
#define GEN_TABLES                  \
    gen_table(rtag7_hash_algorithms)

#define gen_table(name) static indigo_core_gentable_t* name##_table;
GEN_TABLES
#undef gen_table

static const indigo_core_gentable_ops_t stub_ops;

static indigo_error_t
pipeline_bvs_table_stub_add(void *table_priv, of_list_bsn_tlv_t *key,
                            of_list_bsn_tlv_t *value, void **entry_priv)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_stub_modify(void *table_priv, void *entry_priv,
                               of_list_bsn_tlv_t *key,
                               of_list_bsn_tlv_t *value)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_stub_delete(void *table_priv, void *entry_priv,
                               of_list_bsn_tlv_t *key)
{
    return INDIGO_ERROR_NONE;
}

static void
pipeline_bvs_table_stub_get_stats(void *table_priv, void *entry_priv,
                                  of_list_bsn_tlv_t *key,
                                  of_list_bsn_tlv_t *stats)
{
}

static const indigo_core_gentable_ops_t stub_ops = {
    .add = pipeline_bvs_table_stub_add,
    .modify = pipeline_bvs_table_stub_modify,
    .del = pipeline_bvs_table_stub_delete,
    .get_stats = pipeline_bvs_table_stub_get_stats,
};

void
pipeline_bvs_table_stub_register(void)
{
#define gen_table(name) \
    indigo_core_gentable_register(#name, &stub_ops, NULL, 8, 2, &name##_table);
    GEN_TABLES
#undef gen_table
}

void
pipeline_bvs_table_stub_unregister(void)
{
#define gen_table(name) \
    indigo_core_gentable_unregister(name##_table);
    GEN_TABLES
#undef gen_table
}
