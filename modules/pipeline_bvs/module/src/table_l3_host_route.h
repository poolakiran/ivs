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

#ifndef TABLE_L3_HOST_ROUTE_H
#define TABLE_L3_HOST_ROUTE_H

struct l3_host_route_key {
    uint32_t vrf;
    uint32_t ipv4;
};
AIM_STATIC_ASSERT(l3_host_route_KEY_SIZE, sizeof(struct l3_host_route_key) == 8);

struct l3_host_route_value {
    struct next_hop next_hop;
    bool cpu;
};

struct l3_host_route_entry {
    bighash_entry_t hash_entry;
    struct l3_host_route_key key;
    struct l3_host_route_value value;
};

void pipeline_bvs_table_l3_host_route_register(void);
void pipeline_bvs_table_l3_host_route_unregister(void);
struct l3_host_route_entry *pipeline_bvs_table_l3_host_route_lookup(uint32_t vrf, uint32_t ipv4);

#endif
