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

#ifndef TABLE_MULTICAST_VLAN_H
#define TABLE_MULTICAST_VLAN_H

struct multicast_replication_group_entry;

struct multicast_vlan_key {
    uint16_t vlan_vid;
};
AIM_STATIC_ASSERT(MULTICAST_VLAN_KEY_SIZE, sizeof(struct multicast_vlan_key) == 2);

struct multicast_vlan_value {
    bool igmp_snooping;
    bool l2_multicast_lookup;
    struct multicast_replication_group_entry *default_replication_group;
};

struct multicast_vlan_entry {
    bighash_entry_t hash_entry;
    struct multicast_vlan_key key;
    struct multicast_vlan_value value;
};

void pipeline_bvs_table_multicast_vlan_register(void);
void pipeline_bvs_table_multicast_vlan_unregister(void);
struct multicast_vlan_entry *pipeline_bvs_table_multicast_vlan_lookup(uint16_t vlan_vid);

#endif
