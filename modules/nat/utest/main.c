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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nat/nat.h>
#include <assert.h>
#include <AIM/aim.h>
#include <AIM/aim_log.h>
#include <indigo/of_state_manager.h>

static const indigo_core_gentable_ops_t *nat_ops;

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    nat_init();
    AIM_ASSERT(nat_ops != NULL);

    return 0;
}

void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *ops,
    void *table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    *gentable = NULL;
    nat_ops = ops;
}
