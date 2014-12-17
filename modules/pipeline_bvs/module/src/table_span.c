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
#include <indigo/of_state_manager.h>
#include "pipeline_bvs_int.h"

static indigo_core_gentable_t *span_table;
static const indigo_core_gentable_ops_t span_ops;
uint16_t pipeline_bvs_table_span_id;

static void cleanup_value(struct span_value *value);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct span_key *key)
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
            AIM_LOG_ERROR("SPAN name too long");
            return INDIGO_ERROR_PARAM;
        }
        if (strnlen((char *)name.data, name.bytes) != name.bytes) {
            AIM_LOG_ERROR("SPAN name includes null bytes");
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
parse_value(of_list_bsn_tlv_t *tlvs, struct span_value *value)
{
    value->lag = NULL;
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected gentable value TLV, instead got end of list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t key;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &key);
        if (table_id == pipeline_bvs_table_lag_id) {
            value->lag = pipeline_bvs_table_lag_acquire(&key);
            if (value->lag == NULL) {
                AIM_LOG_ERROR("Nonexistent LAG in SPAN group");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in SPAN group");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference value TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct span_value *value)
{
    if (value->lag) {
        pipeline_bvs_table_lag_release(value->lag);
        value->lag = NULL;
    }
}

static indigo_error_t
span_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct span_group span;

    span.id = OF_GROUP_ANY;

    if ((rv = parse_key(key, &span.key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value, &span.value)) < 0) {
        return rv;
    }

    *entry_priv = aim_memdup(&span, sizeof(span));

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
span_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    struct span_value new_value;
    struct span_group *span = entry_priv;

    if ((rv = parse_value(value, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&span->value);
    span->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
span_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct span_group *span = entry_priv;
    cleanup_value(&span->value);
    aim_free(span);
    return INDIGO_ERROR_NONE;
}

static void
span_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t span_ops = {
    .add2 = span_add,
    .modify2 = span_modify,
    .del2 = span_delete,
    .get_stats = span_get_stats,
};

void
pipeline_bvs_table_span_register(void)
{
    indigo_core_gentable_register("span", &span_ops, NULL, 128, 128,
                                  &span_table);
    pipeline_bvs_table_span_id = indigo_core_gentable_id(span_table);
}

void
pipeline_bvs_table_span_unregister(void)
{
    indigo_core_gentable_unregister(span_table);
}

struct span_group *
pipeline_bvs_table_span_acquire(of_object_t *key)
{
    return indigo_core_gentable_acquire(span_table, key);
}

void
pipeline_bvs_table_span_release(struct span_group *span)
{
    if (span->id != OF_GROUP_ANY) {
        indigo_core_group_release(span->id);
    } else {
        /* HACK */
        of_object_t *key = of_bsn_tlv_name_new(OF_VERSION_1_3);
        of_octets_t name = { .data = (uint8_t *)span->key.name, .bytes = strlen(span->key.name) };
        if (of_bsn_tlv_name_value_set(key, &name) < 0) {
            AIM_DIE("Unexpected error creating SPAN key in pipeline_bvs_table_span_release");
        }
        indigo_core_gentable_release(span_table, key);
        of_object_delete(key);
    }
}

struct span_group *
pipeline_bvs_table_span_lookup(of_object_t *key)
{
    return indigo_core_gentable_lookup(span_table, key);
}
