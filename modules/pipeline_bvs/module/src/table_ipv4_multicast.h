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

#ifndef TABLE_IPV4_MULTICAST_H
#define TABLE_IPV4_MULTICAST_H

#include <timer_wheel/timer_wheel.h>

struct multicast_replication_group;

struct ipv4_multicast_key {
    uint32_t multicast_interface_id;
    uint32_t vrf;
    uint32_t ipv4;
    uint32_t ipv4_src;
};
AIM_STATIC_ASSERT(IPV4_MULTICAST_KEY_SIZE, sizeof(struct ipv4_multicast_key) == 16);

struct ipv4_multicast_value {
    struct multicast_replication_group_entry *multicast_replication_group;
    uint32_t idle_timeout;
};

struct ipv4_multicast_entry {
    bighash_entry_t hash_entry;
    timer_wheel_entry_t timer_entry;
    struct ipv4_multicast_key key;
    struct ipv4_multicast_value value;
    struct stats_handle stats_handle;
    uint64_t last_hit_check_packets;
};

void pipeline_bvs_table_ipv4_multicast_register(void);
void pipeline_bvs_table_ipv4_multicast_unregister(void);
struct ipv4_multicast_entry *pipeline_bvs_table_ipv4_multicast_lookup(uint16_t vlan_vid, uint32_t vrf, uint32_t ipv4, uint32_t ipv4_src);

#endif
