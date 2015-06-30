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

#ifndef TABLE_MULTICAST_REPLICATION_H
#define TABLE_MULTICAST_REPLICATION_H

struct multicast_replication_group_entry;

struct multicast_replication_key {
    uint16_t vlan_vid; /* VLAN_INVALID if not set */
    struct multicast_replication_group_entry *multicast_replication_group;
    struct lag_group *lag;
};

struct multicast_replication_value {
    of_mac_addr_t new_eth_src;
};

struct multicast_replication_entry {
    struct list_links links; /* multicast_replication_group_entry.members */
    bool l3;
    struct multicast_replication_key key;
    struct multicast_replication_value value;
};

void pipeline_bvs_table_multicast_replication_register(void);
void pipeline_bvs_table_multicast_replication_unregister(void);

#endif
