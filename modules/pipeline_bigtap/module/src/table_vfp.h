/****************************************************************
 *
 *        Copyright 2015, Big Switch Networks, Inc.
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

#ifndef TABLE_VFP_H
#define TABLE_VFP_H

#include <stdint.h>
#include <tcam/tcam.h>
#include <loci/loci.h>
#include <stats/stats.h>
#include <AIM/aim_utils.h>

#define TABLE_ID_VFP 3

struct vfp_key {
    uint32_t in_port;
    uint16_t eth_type;
    uint16_t tp_src;
    uint16_t tp_dst;
    uint16_t tcp_flags;
    uint8_t ip_proto;
    uint8_t pad[3];
};
AIM_STATIC_ASSERT(VFP_KEY_SIZE, sizeof(struct vfp_key) == 16);

struct vfp_value {
    bool cpu;
};

struct vfp_entry {
    struct tcam_entry tcam_entry;
    struct vfp_value value;
    struct stats_handle stats_handle;
};

void pipeline_bigtap_table_vfp_register(void);
void pipeline_bigtap_table_vfp_unregister(void);
struct vfp_entry *pipeline_bigtap_table_vfp_lookup(const struct vfp_key *key);

#endif
