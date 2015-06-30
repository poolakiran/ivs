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
#include <sflowa/sflowa.h>
#include <slshared/slshared_config.h>
#include <debug_counter/debug_counter.h>
#include <packet_trace/packet_trace.h>

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
#include "table_floating_ip_forward.h"
#include "table_floating_ip_reverse.h"
#include "table_qos_weight.h"
#include "table_breakout.h"
#include "table_arp_offload.h"
#include "table_arp_cache.h"
#include "table_span.h"
#include "table_ecmp.h"
#include "group_lag.h"
#include "group_ecmp.h"
#include "group_span.h"
#include "qos.h"
#include "stats.h"
#include "pktin.h"
#include "table_priority_to_queue.h"
#include "table_fspan_vlan.h"
#include "table_port_block.h"
#include "table_multicast_vlan.h"

#define AIM_LOG_MODULE_NAME pipeline_bvs
#include <AIM/aim_log.h>

#define UNUSED __attribute__((unused))

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

#define INTERNAL_PRIORITY_INVALID UINT32_MAX

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
    TABLE_ID_FLOATING_IP_FORWARD = 21,
    TABLE_ID_FLOATING_IP_REVERSE = 22,
};

enum group_table_id {
    GROUP_TABLE_ID_LAG = 0,
    GROUP_TABLE_ID_ECMP = 1,
    GROUP_TABLE_ID_SPAN = 2,
};

/*
 * QUEUE_PRIORITY distinguishes the class into which the
 * outgoing packet will be enqueued.
 * QUEUE_PRIORITY 0 maps to class 1,
 * QUEUE_PRIORITY 1 maps to class 2 and so on.
 */
enum queue_priority {
    QUEUE_PRIORITY_INVALID = -1,
    QUEUE_PRIORITY_VLAN_PRIO_0_1 = 0,
    QUEUE_PRIORITY_VLAN_PRIO_2_3 = 1,
    QUEUE_PRIORITY_VLAN_PRIO_4_5 = 2,
    QUEUE_PRIORITY_VLAN_PRIO_6_7 = 3,
    QUEUE_PRIORITY_SPAN = 4,
    QUEUE_PRIORITY_UNUSED_1 = 5,
    QUEUE_PRIORITY_UNUSED_2 = 6,
    QUEUE_PRIORITY_INBAND = 7,
    QUEUE_PRIORITY_PDU = 8,
};

struct ctx {
    struct ind_ovs_parsed_key *key;
    struct xbuf *stats;
    struct action_context *actx;
    uint32_t hash;
    int recursion_depth;

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
    struct lag_group *ingress_lag;
    uint16_t cur_tag;
    uint32_t ingress_port_group_id;
    uint32_t skb_priority;
    uint32_t internal_priority;
};

enum pipeline_bvs_version {
    V1_0,
    V2_0,
};

extern enum pipeline_bvs_version version;

extern uint16_t pipeline_bvs_table_lag_id;
extern uint16_t pipeline_bvs_table_span_id;
extern uint16_t pipeline_bvs_table_ecmp_id;
extern uint16_t pipeline_bvs_table_port_block_id;

/* Utility functions */

static inline uint32_t
group_to_table_id(uint32_t group_id)
{
    return group_id >> 24;
}

bool pipeline_bvs_check_tcam_mask(const of_match_fields_t *_mask, const of_match_fields_t *_minimum, const of_match_fields_t *_maximum);

static inline const char *
lag_name(struct lag_group *lag)
{
    if (lag == NULL) {
        return "(null)";
    } else {
        return lag->key.name;
    }
}

static inline const char *
span_name(struct span_group *span)
{
    if (span == NULL) {
        return "(null)";
    } else {
        return span->key.name;
    }
}

#endif
