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

#ifndef TABLE_FLOATING_IP_REVERSE_H
#define TABLE_FLOATING_IP_REVERSE_H

struct floating_ip_reverse_key {
    uint32_t ipv4_dst;
    uint16_t vlan_vid;
    of_mac_addr_t eth_dst;
};
AIM_STATIC_ASSERT(FLOATING_IP_REVERSE_KEY_SIZE, sizeof(struct floating_ip_reverse_key) == 12);

struct floating_ip_reverse_value {
    uint32_t new_ipv4_dst;
    uint16_t new_vlan_vid;
    of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
};

struct floating_ip_reverse_entry {
    bighash_entry_t hash_entry;
    struct floating_ip_reverse_key key;
    struct floating_ip_reverse_value value;
};

void pipeline_bvs_table_floating_ip_reverse_register(void);
void pipeline_bvs_table_floating_ip_reverse_unregister(void);
struct floating_ip_reverse_entry *pipeline_bvs_table_floating_ip_reverse_lookup(uint16_t vlan_vid, uint32_t ipv4_dst, const uint8_t *eth_dst);

#endif
