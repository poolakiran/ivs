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

static indigo_core_gentable_t *qos_weight_table;
static const indigo_core_gentable_ops_t qos_weight_ops;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected queue_id key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_QUEUE_ID) {
        uint32_t queue_id;
        of_bsn_tlv_queue_id_value_get(&tlv, &queue_id);
        if (queue_id >= 9) {
            AIM_LOG_ERROR("invalid queue id");
            return INDIGO_ERROR_PARAM;
        }
    } else {
        AIM_LOG_ERROR("expected queue_id key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected queue_weight value TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_QUEUE_WEIGHT) {
        uint32_t queue_weight;
        of_bsn_tlv_queue_weight_value_get(&tlv, &queue_weight);
        if (queue_weight == 0 || queue_weight >= 128) {
            AIM_LOG_ERROR("invalid queue weight");
            return INDIGO_ERROR_PARAM;
        }
    } else {
        AIM_LOG_ERROR("expected queue_weight value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
qos_weight_add(void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;

    if ((rv = parse_key(key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value)) < 0) {
        return rv;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
qos_weight_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;

    if ((rv = parse_value(value)) < 0) {
        return rv;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
qos_weight_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    return INDIGO_ERROR_NONE;
}

static void
qos_weight_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t qos_weight_ops = {
    .add = qos_weight_add,
    .modify = qos_weight_modify,
    .del = qos_weight_delete,
    .get_stats = qos_weight_get_stats,
};

void
pipeline_bvs_table_qos_weight_register(void)
{
    indigo_core_gentable_register("qos_weight", &qos_weight_ops, NULL, 10, 4,
                                  &qos_weight_table);
}

void
pipeline_bvs_table_qos_weight_unregister(void)
{
    indigo_core_gentable_unregister(qos_weight_table);
}
