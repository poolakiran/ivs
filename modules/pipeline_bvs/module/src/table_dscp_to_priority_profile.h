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

#ifndef TABLE_DSCP_TO_PRIORITY_PROFILE_H
#define TABLE_DSCP_TO_PRIORITY_PROFILE_H

#define NUM_DSCP 64
#define MAX_INTERNAL_PRIORITY 9

struct dscp_to_priority_profile_key {
    char name[64];
};

struct dscp_to_priority_profile_bucket {
    uint8_t qos_priority; /* (0,4) */
};

struct dscp_to_priority_profile_value {
    struct dscp_to_priority_profile_bucket buckets[NUM_DSCP];
};

struct dscp_to_priority_profile_entry {
    list_links_t links;
    struct dscp_to_priority_profile_key key;
    struct dscp_to_priority_profile_value value;
};

void pipeline_bvs_table_dscp_to_priority_profile_register(void);
void pipeline_bvs_table_dscp_to_priority_profile_unregister(void);
struct dscp_to_priority_profile_entry *pipeline_bvs_table_dscp_to_priority_profile_acquire(of_object_t *obj);
void pipeline_bvs_table_dscp_to_priority_profile_release(struct dscp_to_priority_profile_entry *entry);
struct dscp_to_priority_profile_entry *pipeline_bvs_table_dscp_to_priority_profile_lookup(of_object_t *obj);
extern uint16_t pipeline_bvs_table_dscp_to_priority_profile_id;
extern list_head_t pipeline_bvs_table_dscp_to_priority_profile_entries;

#endif
