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

#ifndef TABLE_VLAN_H
#define TABLE_VLAN_H

struct vlan_key {
    uint16_t vlan_vid;
};
AIM_STATIC_ASSERT(VLAN_KEY_SIZE, sizeof(struct vlan_key) == 2);

struct vlan_value {
    uint32_t l3_interface_class_id;
    uint32_t vrf;
    uint32_t *ports; /* first tagged ports, then untagged ports */
    int num_ports;
    int num_tagged_ports;
    uint32_t internal_priority;
};

struct vlan_entry {
    bighash_entry_t hash_entry;
    struct vlan_key key;
    struct vlan_value value;
};

void pipeline_bvs_table_vlan_register(void);
void pipeline_bvs_table_vlan_unregister(void);
struct vlan_entry *pipeline_bvs_table_vlan_lookup(uint16_t vlan_vid);

#endif
