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

#ifndef TABLE_SOURCE_MISS_OVERRIDE_H
#define TABLE_SOURCE_MISS_OVERRIDE_H

struct source_miss_override_key {
    uint32_t in_port;
    uint16_t vlan_vid;
    uint16_t pad;
};
AIM_STATIC_ASSERT(SOURCE_MISS_OVERRIDE_KEY_SIZE, sizeof(struct source_miss_override_key) == 8);

struct source_miss_override_value {
    bool cpu;
};

struct source_miss_override_entry {
    bighash_entry_t hash_entry;
    struct source_miss_override_key key;
    struct source_miss_override_value value;
};

void pipeline_bvs_table_source_miss_override_register(void);
void pipeline_bvs_table_source_miss_override_unregister(void);
struct source_miss_override_entry *pipeline_bvs_table_source_miss_override_lookup(uint16_t vlan_vid, uint32_t in_port);

#endif
