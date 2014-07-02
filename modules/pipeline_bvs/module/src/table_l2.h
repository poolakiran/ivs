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

#ifndef TABLE_L2_H
#define TABLE_L2_H

struct l2_key {
    uint16_t vlan_vid;
    of_mac_addr_t mac;
};
AIM_STATIC_ASSERT(L2_KEY_SIZE, sizeof(struct l2_key) == 8);

struct l2_value {
    struct lag_group *lag; /* NULL means discard */
};

struct l2_entry {
    bighash_entry_t hash_entry;
    struct l2_key key;
    struct l2_value value;
    struct ind_ovs_flow_stats stats;
    uint64_t last_hit_check_packets;
};

void pipeline_bvs_table_l2_register(void);
void pipeline_bvs_table_l2_unregister(void);
struct l2_entry *pipeline_bvs_table_l2_lookup(uint16_t vlan_vid, const uint8_t *mac);

#endif
