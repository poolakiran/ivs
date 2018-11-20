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

#ifndef TABLE_PRIORITY_TO_PCP_PROFILE_H
#define TABLE_PRIORITY_TO_PCP_PROFILE_H

#define NUM_INTERNAL_PRIORITY 10
#define QOS_MAP_DSCP_UNSET 0xFFFF

struct priority_to_pcp_profile_key {
    char name[64];
};

struct priority_to_pcp_profile_bucket {
    uint8_t vlan_pcp;
    uint16_t dscp;
};

struct priority_to_pcp_profile_value {
    struct priority_to_pcp_profile_bucket buckets[NUM_INTERNAL_PRIORITY];
};

struct priority_to_pcp_profile_entry {
    list_links_t links;
    struct priority_to_pcp_profile_key key;
    struct priority_to_pcp_profile_value value;
};

void pipeline_bvs_table_priority_to_pcp_profile_register(void);
void pipeline_bvs_table_priority_to_pcp_profile_unregister(void);
struct priority_to_pcp_profile_entry *pipeline_bvs_table_priority_to_pcp_profile_acquire(of_object_t *obj);
void pipeline_bvs_table_priority_to_pcp_profile_release(struct priority_to_pcp_profile_entry *entry);
struct priority_to_pcp_profile_entry *pipeline_bvs_table_priority_to_pcp_profile_lookup(of_object_t *obj);
extern uint16_t pipeline_bvs_table_priority_to_pcp_profile_id;
extern list_head_t pipeline_bvs_table_priority_to_pcp_profile_entries;

#endif
