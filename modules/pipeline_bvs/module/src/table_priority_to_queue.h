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

#ifndef TABLE_PRIORITY_TO_QUEUE_H
#define TABLE_PRIORITY_TO_QUEUE_H

struct priority_to_queue_key {
    uint32_t internal_priority;
};
AIM_STATIC_ASSERT(PRIORITY_TO_QUEUE_KEY_SIZE, sizeof(struct priority_to_queue_key) == 4);

struct priority_to_queue_value {
    uint32_t queue_id;
};

struct priority_to_queue_entry {
    struct priority_to_queue_key key;
    struct priority_to_queue_value value;
};

void pipeline_bvs_table_priority_to_queue_register(void);
void pipeline_bvs_table_priority_to_queue_unregister(void);
struct priority_to_queue_entry* pipeline_bvs_table_priority_to_queue_lookup(uint32_t internal_priority);

#endif
