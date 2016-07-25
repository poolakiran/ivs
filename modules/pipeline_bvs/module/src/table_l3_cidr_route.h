/****************************************************************
 *
 *        Copyright 2014-2016, Big Switch Networks, Inc.
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
    uint16_t eth_type;
    uint32_t vrf;
    union {
        uint32_t ipv4;
        of_ipv6_t ipv6;
    };
    uint8_t mask_len;
};

struct l3_cidr_route_value {
    struct next_hop next_hop;
    bool cpu;
};

struct l3_cidr_route_entry {
    struct l3_cidr_route_key key;
    struct l3_cidr_route_value value;
};

void pipeline_bvs_table_l3_cidr_route_register(void);
void pipeline_bvs_table_l3_cidr_route_unregister(void);
struct l3_cidr_route_entry *pipeline_bvs_table_l3_cidr_route_ipv4_lookup(uint32_t vrf, uint32_t ipv4);
struct l3_cidr_route_entry *pipeline_bvs_table_l3_cidr_route_ipv6_lookup(uint32_t vrf, uint32_t *ipv6);

#endif
