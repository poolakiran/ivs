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

#ifndef TABLE_PORT_FEATURES_H
#define TABLE_PORT_FEATURES_H

struct port_features_key {
    uint32_t port_no;
};
AIM_STATIC_ASSERT(PORT_FEATURES_KEY_SIZE, sizeof(struct port_features_key) == 4);

struct port_features_value {
    bool ndp_offload;
};

struct port_features_entry {
    bighash_entry_t hash_entry;
    struct port_features_key key;
    struct port_features_value value;
};

void pipeline_bvs_table_port_features_register(void);
void pipeline_bvs_table_port_features_unregister(void);
struct port_features_entry *pipeline_bvs_table_port_features_lookup(uint32_t port_no);

#endif
