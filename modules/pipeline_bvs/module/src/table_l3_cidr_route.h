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

#ifndef TABLE_L3_CIDR_ROUTE_H
#define TABLE_L3_CIDR_ROUTE_H

struct l3_cidr_route_key {
    uint32_t vrf;
    uint32_t ipv4;
};
AIM_STATIC_ASSERT(L3_CIDR_ROUTE_KEY_SIZE, sizeof(struct l3_cidr_route_key) == 8);

struct l3_cidr_route_value {
    /* Either LAG or ECMP or OF_GROUP_ANY for null route */
    uint32_t group_id;

    /* Only used if group_id is a LAG */
    of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
    uint16_t new_vlan_vid;

    /* Always used */
    bool cpu;
};

struct l3_cidr_route_entry {
    struct tcam_entry tcam_entry;
    struct l3_cidr_route_value value;
};

void pipeline_bvs_table_l3_cidr_route_register(void);
void pipeline_bvs_table_l3_cidr_route_unregister(void);
struct l3_cidr_route_entry *pipeline_bvs_table_l3_cidr_route_lookup(const struct l3_cidr_route_key *key);

#endif
