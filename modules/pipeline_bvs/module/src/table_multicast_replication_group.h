/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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

#ifndef TABLE_MULTICAST_REPLICATION_GROUP_H
#define TABLE_MULTICAST_REPLICATION_GROUP_H

struct multicast_replication_group_key {
    char name[64];
};

struct multicast_replication_group_entry {
    struct multicast_replication_group_key key;
    struct list_head members; /* struct multicast_replication_entry through links */
};

void pipeline_bvs_table_multicast_replication_group_register(void);
void pipeline_bvs_table_multicast_replication_group_unregister(void);
struct multicast_replication_group_entry *pipeline_bvs_table_multicast_replication_group_acquire(of_object_t *obj);
void pipeline_bvs_table_multicast_replication_group_release(struct multicast_replication_group_entry *multicast_replication_group);
struct multicast_replication_group_entry *pipeline_bvs_table_multicast_replication_group_lookup(of_object_t *obj);

#endif
