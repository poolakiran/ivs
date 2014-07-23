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

#ifndef TABLE_VLAN_XLATE_H
#define TABLE_VLAN_XLATE_H

struct vlan_xlate_key {
    uint32_t vlan_xlate_port_group_id;
    uint16_t vlan_vid;
    uint16_t pad;
};
AIM_STATIC_ASSERT(VLAN_XLATE_KEY_SIZE, sizeof(struct vlan_xlate_key) == 8);

struct vlan_xlate_value {
    uint16_t new_vlan_vid;
};

struct vlan_xlate_entry {
    bighash_entry_t hash_entry;
    struct vlan_xlate_key key;
    struct vlan_xlate_value value;
};

void pipeline_bvs_table_vlan_xlate_register(void);
void pipeline_bvs_table_vlan_xlate_unregister(void);
struct vlan_xlate_entry *pipeline_bvs_table_vlan_xlate_lookup(uint32_t vlan_xlate_port_group_id, uint16_t vlan_vid);

#endif
