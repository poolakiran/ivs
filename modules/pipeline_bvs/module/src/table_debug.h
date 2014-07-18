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

#ifndef TABLE_DEBUG_H
#define TABLE_DEBUG_H

struct debug_key {
    uint32_t in_port;
    of_mac_addr_t eth_src;
    of_mac_addr_t eth_dst;
    uint16_t eth_type;
    uint16_t vlan_vid;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    uint8_t ip_proto;
    uint8_t ip_tos; /* DSCP and ECN */
    uint16_t tp_src;
    uint16_t tp_dst;
    uint16_t tcp_flags;
};
AIM_STATIC_ASSERT(DEBUG_KEY_SIZE, sizeof(struct debug_key) == 36);

struct debug_value {
    struct span_group *span; /* NULL if unused */
    bool cpu;
    bool drop;
};

struct debug_entry {
    struct tcam_entry tcam_entry;
    struct debug_value value;
    struct stats_handle stats_handle;
};

void pipeline_bvs_table_debug_register(void);
void pipeline_bvs_table_debug_unregister(void);
struct debug_entry *pipeline_bvs_table_debug_lookup(const struct debug_key *key);

#endif
