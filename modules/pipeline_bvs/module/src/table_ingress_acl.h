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

#ifndef TABLE_INGRESS_ACL_H
#define TABLE_INGRESS_ACL_H

struct ingress_acl_key {
    uint32_t in_port;
    uint16_t eth_type;
    uint16_t vlan_vid;
    uint8_t ip_proto;
    uint8_t pad[3];
    uint32_t vrf;
    uint32_t l3_interface_class_id;
    uint32_t l3_src_class_id;
    union {
        uint32_t ipv4_src;
        of_ipv6_t ipv6_src;
    };
    union {
        uint32_t ipv4_dst;
        of_ipv6_t ipv6_dst;
    };
    uint16_t tp_src;
    uint16_t tp_dst;
    uint16_t tcp_flags;
    uint16_t pad2;
};
AIM_STATIC_ASSERT(INGRESS_ACL_KEY_SIZE, sizeof(struct ingress_acl_key) == 64);

struct ingress_acl_value {
    struct next_hop next_hop;
    bool cpu;
    bool drop;
};

struct ingress_acl_entry {
    struct tcam_entry tcam_entry;
    struct ingress_acl_value value;
    struct stats_handle stats_handle;
};

void pipeline_bvs_table_ingress_acl_register(void);
void pipeline_bvs_table_ingress_acl_unregister(void);
struct ingress_acl_entry *pipeline_bvs_table_ingress_acl_lookup(const struct ingress_acl_key *key);

#endif
