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

#ifndef TABLE_SPAN_H
#define TABLE_SPAN_H

/* These datastructures are shared with the legacy SPAN group */

struct span_key {
    char name[64];
};

struct span_value {
    struct lag_group *lag;
};

struct span_group {
    uint32_t id;
    struct span_key key;
    struct span_value value;
};

void pipeline_bvs_table_span_register(void);
void pipeline_bvs_table_span_unregister(void);
struct span_group *pipeline_bvs_table_span_acquire(of_object_t *obj);
void pipeline_bvs_table_span_release(struct span_group *span);
struct span_group *pipeline_bvs_table_span_lookup(of_object_t *obj);

#endif
