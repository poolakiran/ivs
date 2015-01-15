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

#ifndef TABLE_ARP_OFFLOAD_H
#define TABLE_ARP_OFFLOAD_H

struct arp_offload_key {
    uint16_t vlan_vid;
    uint16_t pad;
    uint32_t ipv4;
};
AIM_STATIC_ASSERT(ARP_OFFLOAD_KEY_SIZE, sizeof(struct arp_offload_key) == 8);

struct arp_offload_entry {
    bighash_entry_t hash_entry;
    struct arp_offload_key key;
};

void pipeline_bvs_table_arp_offload_register(void);
void pipeline_bvs_table_arp_offload_unregister(void);
struct arp_offload_entry *pipeline_bvs_table_arp_offload_lookup(uint16_t vlan_vid, uint32_t ipv4);

#endif
