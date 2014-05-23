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

#ifndef TABLE_VLAN_ACL_H
#define TABLE_VLAN_ACL_H

struct vlan_acl_key {
    uint16_t vlan_vid;
    of_mac_addr_t eth_src;
    of_mac_addr_t eth_dst;
    uint16_t pad;
};
AIM_STATIC_ASSERT(VLAN_ACL_KEY_SIZE, sizeof(struct vlan_acl_key) == 16);

struct vlan_acl_value {
    uint32_t l3_interface_class_id;
    uint32_t l3_src_class_id;
    uint32_t vrf;
};

struct vlan_acl_entry {
    struct tcam_entry tcam_entry;
    struct vlan_acl_value value;
};

void pipeline_bvs_table_vlan_acl_register(void);
void pipeline_bvs_table_vlan_acl_unregister(void);
struct vlan_acl_entry *pipeline_bvs_table_vlan_acl_lookup(const struct vlan_acl_key *key);

#endif
