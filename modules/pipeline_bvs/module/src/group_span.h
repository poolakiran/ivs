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

#ifndef GROUP_SPAN_H
#define GROUP_SPAN_H

struct span_value {
    uint32_t lag_id;
};

struct span_group {
    uint32_t id;
    struct span_value value;
};

void pipeline_bvs_group_span_register(void);
void pipeline_bvs_group_span_unregister(void);
struct span_group *pipeline_bvs_group_span_acquire(uint32_t span_id);
void pipeline_bvs_group_span_release(struct span_group *span);

#endif
