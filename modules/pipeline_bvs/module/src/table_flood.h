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

#ifndef TABLE_FLOOD_H
#define TABLE_FLOOD_H

struct flood_key {
    uint32_t lag_id;
};
AIM_STATIC_ASSERT(FLOOD_KEY_SIZE, sizeof(struct flood_key) == 4);

struct flood_value {
    uint32_t *lag_ids;
    int num_lag_ids;
};

struct flood_entry {
    bighash_entry_t hash_entry;
    struct flood_key key;
    struct flood_value value;
};

void pipeline_bvs_table_flood_register(void);
void pipeline_bvs_table_flood_unregister(void);
struct flood_entry *pipeline_bvs_table_flood_lookup(const struct flood_key *key);

#endif
