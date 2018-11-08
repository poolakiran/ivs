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

#ifndef TABLE_ECMP_H
#define TABLE_ECMP_H

#define ECMP_NAME_LEN 128

/* These datastructures are shared with the legacy ECMP group */

struct ecmp_key {
    char name[ECMP_NAME_LEN];
};

struct ecmp_value {
    int num_buckets;
    struct ecmp_bucket *buckets;
};

struct ecmp_group {
    uint32_t id;
    struct ecmp_key key;
    struct ecmp_value value;
};

struct ecmp_bucket {
    struct next_hop next_hop;
};

void pipeline_bvs_table_ecmp_register(void);
void pipeline_bvs_table_ecmp_unregister(void);
struct ecmp_bucket *pipeline_bvs_table_ecmp_select(struct ecmp_group *ecmp, uint32_t hash);
struct ecmp_group *pipeline_bvs_table_ecmp_acquire(of_object_t *obj);
void pipeline_bvs_table_ecmp_release(struct ecmp_group *ecmp);
struct ecmp_group *pipeline_bvs_table_ecmp_lookup(of_object_t *obj);

#endif
