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

#ifndef TABLE_INGRESS_MIRROR_H
#define TABLE_INGRESS_MIRROR_H

struct ingress_mirror_key {
    uint32_t in_port;
};
AIM_STATIC_ASSERT(INGRESS_MIRROR_KEY_SIZE, sizeof(struct ingress_mirror_key) == 4);

struct ingress_mirror_value {
    uint32_t span_id;
};

struct ingress_mirror_entry {
    bighash_entry_t hash_entry;
    struct ingress_mirror_key key;
    struct ingress_mirror_value value;
};

void pipeline_bvs_table_ingress_mirror_register(void);
void pipeline_bvs_table_ingress_mirror_unregister(void);
struct ingress_mirror_entry *pipeline_bvs_table_ingress_mirror_lookup(uint32_t port_no);

#endif
