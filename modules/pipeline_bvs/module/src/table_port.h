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

#ifndef TABLE_PORT_H
#define TABLE_PORT_H

struct port_key {
    uint32_t port;
};
AIM_STATIC_ASSERT(PORT_KEY_SIZE, sizeof(struct port_key) == 4);

struct port_value {
    uint32_t lag_id;
    uint32_t egr_port_group_id;
    uint16_t default_vlan_vid;
    unsigned disable_src_mac_check : 1;
    unsigned arp_offload : 1;
    unsigned dhcp_offload : 1;
    unsigned packet_of_death : 1;
    unsigned prioritize_pdus : 1;
};

struct port_entry {
    bighash_entry_t hash_entry;
    struct port_key key;
    struct port_value value;
};

void pipeline_bvs_table_port_register(void);
void pipeline_bvs_table_port_unregister(void);
struct port_entry *pipeline_bvs_table_port_lookup(const struct port_key *key);

#endif
