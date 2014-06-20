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

#ifndef GROUP_LAG_H
#define GROUP_LAG_H

struct lag_value {
    int num_buckets;
    struct lag_bucket *buckets;
};

struct lag_group {
    uint32_t id;
    struct lag_value value;
};

struct lag_bucket {
    uint32_t port_no;
};

void pipeline_bvs_group_lag_register(void);
void pipeline_bvs_group_lag_unregister(void);
struct lag_bucket *pipeline_bvs_group_lag_select(struct lag_group *lag, uint32_t hash);
struct lag_group *pipeline_bvs_group_lag_acquire(uint32_t lag_id);
void pipeline_bvs_group_lag_release(struct lag_group *lag);
struct lag_group *pipeline_bvs_group_lag_lookup(uint32_t lag_id);

#endif
