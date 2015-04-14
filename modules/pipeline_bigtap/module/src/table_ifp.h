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

#ifndef TABLE_IFP_H
#define TABLE_IFP_H

#include <stdint.h>
#include <tcam/tcam.h>
#include <loci/loci.h>
#include <stats/stats.h>
#include <AIM/aim_utils.h>
#include <AIM/aim_bitmap.h>

#define TABLE_ID_IFP 1

struct ifp_key {
    uint32_t in_port;
    uint8_t eth_src[6];
    uint8_t eth_dst[6];
    uint16_t eth_type;
    uint16_t vlan;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    uint32_t ipv6_src[4];
    uint32_t ipv6_dst[4];
    uint8_t ip_proto;
    uint8_t ip_tos; /* DSCP and ECN */
    uint16_t tp_src;
    uint16_t tp_dst;
    uint16_t tcp_flags;

    /* TODO bsn_in_port_512 */
};
AIM_STATIC_ASSERT(IFP_KEY_SIZE, sizeof(struct ifp_key) == 68);

struct ifp_value {
    uint16_t new_vlan_vid;
    aim_bitmap128_t out_port_bitmap;
};

struct ifp_entry {
    struct tcam_entry tcam_entry;
    struct ifp_value value;
    struct stats_handle stats_handle;
};

void pipeline_bigtap_table_ifp_register(void);
void pipeline_bigtap_table_ifp_unregister(void);
struct ifp_entry *pipeline_bigtap_table_ifp_lookup(const struct ifp_key *key);

#endif
