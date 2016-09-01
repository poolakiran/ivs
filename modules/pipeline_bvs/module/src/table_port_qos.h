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

#ifndef TABLE_PORT_QOS_H
#define TABLE_PORT_QOS_H

struct port_qos_key {
    uint32_t port;
};
AIM_STATIC_ASSERT(PORT_KEY_SIZE, sizeof(struct port_qos_key) == 4);

struct port_qos_value {
    struct priority_to_pcp_profile_entry *priority_to_pcp_profile;
    struct dscp_to_priority_profile_entry *dscp_profile;
};

struct port_qos_entry {
    bighash_entry_t hash_entry;
    struct port_qos_key key;
    struct port_qos_value value;
};

void pipeline_bvs_table_port_qos_register(void);
void pipeline_bvs_table_port_qos_unregister(void);
struct port_qos_entry *pipeline_bvs_table_port_qos_lookup(uint32_t port);

#endif
