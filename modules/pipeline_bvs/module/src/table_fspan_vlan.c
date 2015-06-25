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

static indigo_core_gentable_t *fspan_vlan_table;
static const indigo_core_gentable_ops_t fspan_vlan_ops;

uint16_t pipeline_bvs_fspan_vlan_vid = -1;
uint16_t pipeline_bvs_fspan_vlan_vid_mask = -1;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected empty key TLV list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, uint16_t *vlan_vid, uint16_t *vlan_vid_mask)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected queue_weight value TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv, vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan_vid value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VLAN_VID_MASK) {
        of_bsn_tlv_vlan_vid_mask_value_get(&tlv, vlan_vid_mask);
    } else {
        AIM_LOG_ERROR("expected vlan_vid_mask value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
fspan_vlan_add(void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    uint16_t vlan_vid, vlan_vid_mask;

    if ((rv = parse_key(key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value, &vlan_vid, &vlan_vid_mask)) < 0) {
        return rv;
    }

    pipeline_bvs_fspan_vlan_vid = vlan_vid;
    pipeline_bvs_fspan_vlan_vid_mask = vlan_vid_mask;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
fspan_vlan_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    uint16_t vlan_vid, vlan_vid_mask;

    if ((rv = parse_value(value, &vlan_vid, &vlan_vid_mask)) < 0) {
        return rv;
    }

    pipeline_bvs_fspan_vlan_vid = vlan_vid;
    pipeline_bvs_fspan_vlan_vid_mask = vlan_vid_mask;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
fspan_vlan_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    pipeline_bvs_fspan_vlan_vid = -1;
    pipeline_bvs_fspan_vlan_vid_mask = -1;
    return INDIGO_ERROR_NONE;
}

static void
fspan_vlan_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t fspan_vlan_ops = {
    .add = fspan_vlan_add,
    .modify = fspan_vlan_modify,
    .del = fspan_vlan_delete,
    .get_stats = fspan_vlan_get_stats,
};

void
pipeline_bvs_table_fspan_vlan_register(void)
{
    indigo_core_gentable_register("fspan_vlan", &fspan_vlan_ops, NULL, 10, 4,
                                  &fspan_vlan_table);
}

void
pipeline_bvs_table_fspan_vlan_unregister(void)
{
    indigo_core_gentable_unregister(fspan_vlan_table);
}
