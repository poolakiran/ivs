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

#ifndef GROUP_ECMP_H
#define GROUP_ECMP_H

#include "table_ecmp.h"

void pipeline_bvs_group_ecmp_register(void);
void pipeline_bvs_group_ecmp_unregister(void);
struct ecmp_bucket *pipeline_bvs_group_ecmp_select(struct ecmp_group *ecmp, uint32_t hash);
struct ecmp_group *pipeline_bvs_group_ecmp_acquire(uint32_t ecmp_id);
void pipeline_bvs_group_ecmp_release(struct ecmp_group *ecmp);

#endif
