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

#ifndef NEXT_HOP_H
#define NEXT_HOP_H

enum next_hop_type {
    NEXT_HOP_TYPE_NULL,
    NEXT_HOP_TYPE_LAG,
    NEXT_HOP_TYPE_ECMP,
    NEXT_HOP_TYPE_LAG_NOREWRITE,
};

struct next_hop {
    union {
        struct lag_group *lag;
        struct ecmp_group *ecmp;
    };

    /* Only used if type is NEXT_HOP_TYPE_LAG */
    of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
    uint16_t new_vlan_vid;

    enum next_hop_type type;
};

indigo_error_t pipeline_bvs_parse_next_hop(of_list_action_t *actions, struct next_hop *next_hop);
indigo_error_t pipeline_bvs_parse_gentable_next_hop(of_list_bsn_tlv_t *tlvs, struct next_hop *next_hop);
void pipeline_bvs_cleanup_next_hop(struct next_hop *next_hop);
void pipeline_bvs_register_next_hop_datatype(void);
void pipeline_bvs_unregister_next_hop_datatype(void);

#endif
