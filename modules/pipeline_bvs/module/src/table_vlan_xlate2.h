/****************************************************************
 *
 *        Copyright 2016, Big Switch Networks, Inc.
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

#ifndef TABLE_VLAN_XLATE2_H
#define TABLE_VLAN_XLATE2_H

struct vlan_xlate2_key {
    struct lag_group *lag;
    uint16_t vlan_vid;
    uint16_t pad;
    uint32_t pad2;
};
AIM_STATIC_ASSERT(VLAN_XLATE2_KEY_SIZE, sizeof(struct vlan_xlate2_key) == 16);

struct vlan_xlate2_value {
    uint16_t new_vlan_vid;
    uint32_t internal_priority;
};

struct vlan_xlate2_entry {
    bighash_entry_t hash_entry;
    struct vlan_xlate2_key key;
    struct vlan_xlate2_value value;
};

void pipeline_bvs_table_vlan_xlate2_register(void);
void pipeline_bvs_table_vlan_xlate2_unregister(void);
struct vlan_xlate2_entry *pipeline_bvs_table_vlan_xlate2_lookup(struct lag_group *lag, uint16_t vlan_vid);

#endif
