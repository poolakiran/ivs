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

indigo_error_t
pipeline_bvs_parse_next_hop(of_list_action_t *actions, struct next_hop *next_hop)
{
    bool seen_group = false;
    bool seen_new_vlan_vid = false;
    bool seen_new_eth_src = false;
    bool seen_new_eth_dst = false;

    of_action_t act;
    int rv;
    OF_LIST_ACTION_ITER(actions, &act, rv) {
        switch (act.header.object_id) {
        case OF_ACTION_GROUP:
            if (!seen_group) {
                of_action_group_group_id_get(&act.group, &next_hop->group_id);
                seen_group = true;
            } else {
                AIM_LOG_ERROR("duplicate group action in next-hop");
                goto error;
            }
            break;
        case OF_ACTION_SET_FIELD: {
            of_oxm_t oxm;
            of_action_set_field_field_bind(&act.set_field, &oxm.header);
            switch (oxm.header.object_id) {
            case OF_OXM_VLAN_VID:
                if (!seen_new_vlan_vid) {
                    of_oxm_vlan_vid_value_get(&oxm.vlan_vid, &next_hop->new_vlan_vid);
                    next_hop->new_vlan_vid &= ~VLAN_CFI_BIT;
                    seen_new_vlan_vid = true;
                } else {
                    AIM_LOG_ERROR("duplicate set-field vlan_vid action in next-hop");
                    goto error;
                }
                break;
            case OF_OXM_ETH_SRC:
                if (!seen_new_eth_src) {
                    of_oxm_eth_src_value_get(&oxm.eth_src, &next_hop->new_eth_src);
                    seen_new_eth_src = true;
                } else {
                    AIM_LOG_ERROR("duplicate set-field eth_src action in next-hop");
                    goto error;
                }
                break;
            case OF_OXM_ETH_DST:
                if (!seen_new_eth_dst) {
                    of_oxm_eth_dst_value_get(&oxm.eth_dst, &next_hop->new_eth_dst);
                    seen_new_eth_dst = true;
                } else {
                    AIM_LOG_ERROR("duplicate set-field eth_dst action in next-hop");
                    goto error;
                }
                break;
            default:
                break;
            }
            break;
        }
        default:
            break;
        }
    }

    if (seen_group) {
        switch (group_to_table_id(next_hop->group_id)) {
        case GROUP_TABLE_ID_LAG:
            if (!seen_new_vlan_vid || !seen_new_eth_src || !seen_new_eth_dst) {
                AIM_LOG_WARN("Missing required next-hop action");
                return INDIGO_ERROR_COMPAT;
            }
            break;
        case GROUP_TABLE_ID_ECMP:
            if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
                AIM_LOG_WARN("Unexpected action in ECMP next-hop");
            }
            break;
        default:
            AIM_LOG_WARN("Unexpected group table ID in next-hop");
            return INDIGO_ERROR_COMPAT;
        }
    } else {
        /* No group action, null route */
        next_hop->group_id = OF_GROUP_ANY;

        if (seen_new_vlan_vid || seen_new_eth_src || seen_new_eth_dst) {
            AIM_LOG_WARN("Unexpected action in null next-hop");
        }
    }

    return INDIGO_ERROR_NONE;

error:
    return INDIGO_ERROR_COMPAT;
}

void
pipeline_bvs_cleanup_next_hop(struct next_hop *next_hop)
{
}
