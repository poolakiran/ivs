/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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

#ifndef PIPELINE_BVS_SUPPORT_H
#define PIPELINE_BVS_SUPPORT_H

#include <stdlib.h>
#include <arpa/inet.h>

#include <indigo/error.h>
#include <xbuf/xbuf.h>
#include <ivs/ivs.h>
#include <loci/loci.h>
#include <pipeline/pipeline.h>
#include <murmur/murmur.h>
#include <indigo/of_connection_manager.h>
#include <indigo/of_state_manager.h>
#include <BigHash/bighash.h>
#include <AIM/aim_list.h>
#include <tcam/tcam.h>
#include <action/action.h>

#include "next_hop.h"
#include "table_port.h"
#include "table_vlan_xlate.h"
#include "table_egr_vlan_xlate.h"
#include "table_vlan.h"
#include "table_l2.h"
#include "table_my_station.h"
#include "table_l3_host_route.h"
#include "table_l3_cidr_route.h"
#include "table_ingress_acl.h"
#include "table_flood.h"
#include "table_debug.h"
#include "table_ingress_mirror.h"
#include "table_egress_mirror.h"
#include "table_egress_acl.h"
#include "table_vlan_acl.h"
#include "table_source_miss_override.h"
#include "table_qos_weight.h"
#include "group_lag.h"
#include "group_ecmp.h"
#include "group_span.h"

#define AIM_LOG_MODULE_NAME pipeline_bvs
#include <AIM/aim_log.h>

#define UNUSED __attribute__((unused))

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

enum table_id {
    TABLE_ID_L2 = 0,
    TABLE_ID_VLAN = 1,
    TABLE_ID_PORT = 2,
    TABLE_ID_VLAN_XLATE = 3,
    TABLE_ID_EGR_VLAN_XLATE = 4,
    TABLE_ID_MY_STATION = 5,
    TABLE_ID_L3_HOST_ROUTE = 6,
    TABLE_ID_L3_CIDR_ROUTE = 7,
    TABLE_ID_FLOOD = 11,
    TABLE_ID_INGRESS_ACL = 12,
    TABLE_ID_DEBUG = 15,
    TABLE_ID_INGRESS_MIRROR = 16,
    TABLE_ID_EGRESS_MIRROR = 17,
    TABLE_ID_EGRESS_ACL = 18,
    TABLE_ID_VLAN_ACL = 19,
    TABLE_ID_SOURCE_MISS_OVERRIDE = 20,
};

enum group_table_id {
    GROUP_TABLE_ID_LAG = 0,
    GROUP_TABLE_ID_ECMP = 1,
    GROUP_TABLE_ID_SPAN = 2,
};

struct ctx {
    struct ind_ovs_parsed_key *key;
    struct xbuf *stats;
    struct action_context *actx;
    uint32_t hash;

    /* Output state */
    bool drop;
    bool pktin_agent;
    bool pktin_controller;
    uint64_t pktin_metadata;

    /* Internal state */
    uint16_t original_vlan_vid;
    uint16_t internal_vlan_vid;
    uint32_t vrf;
    uint32_t l3_interface_class_id;
    uint32_t l3_src_class_id;
    uint32_t ingress_lag_id;
};

/* Utility functions */

static inline uint32_t
group_to_table_id(uint32_t group_id)
{
    return group_id >> 24;
}

bool pipeline_bvs_check_tcam_mask(const of_match_fields_t *_mask, const of_match_fields_t *_minimum, const of_match_fields_t *_maximum);

#endif
