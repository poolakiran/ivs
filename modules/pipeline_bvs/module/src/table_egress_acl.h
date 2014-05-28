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

#ifndef TABLE_EGRESS_ACL_H
#define TABLE_EGRESS_ACL_H

struct egress_acl_key {
    unsigned vlan_vid : 12;
    unsigned l3_interface_class_id : 12;
    unsigned egr_port_group_id : 8;
};
AIM_STATIC_ASSERT(EGRESS_ACL_KEY_SIZE, sizeof(struct egress_acl_key) == 4);

struct egress_acl_value {
    bool drop;
};

struct egress_acl_entry {
    struct tcam_entry tcam_entry;
    struct egress_acl_value value;
};

void pipeline_bvs_table_egress_acl_register(void);
void pipeline_bvs_table_egress_acl_unregister(void);
struct egress_acl_entry *pipeline_bvs_table_egress_acl_lookup(const struct egress_acl_key *key);

#endif
