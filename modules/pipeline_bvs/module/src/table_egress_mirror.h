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

#ifndef TABLE_EGRESS_MIRROR_H
#define TABLE_EGRESS_MIRROR_H

struct egress_mirror_key {
    uint32_t out_port;
};
AIM_STATIC_ASSERT(EGRESS_MIRROR_KEY_SIZE, sizeof(struct egress_mirror_key) == 4);

struct egress_mirror_value {
    uint32_t span_id;
};

struct egress_mirror_entry {
    bighash_entry_t hash_entry;
    struct egress_mirror_key key;
    struct egress_mirror_value value;
};

void pipeline_bvs_table_egress_mirror_register(void);
void pipeline_bvs_table_egress_mirror_unregister(void);
struct egress_mirror_entry *pipeline_bvs_table_egress_mirror_lookup(uint32_t in_port);

#endif
