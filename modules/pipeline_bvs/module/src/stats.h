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

#ifndef PIPELINE_BVS_STATS_H
#define PIPELINE_BVS_STATS_H

#define PIPELINE_STATS \
    stat(INGRESS) \
    stat(PDU) \
    stat(BAD_PORT) \
    stat(VLAN_XLATE_MISS) \
    stat(BAD_VLAN) \
    stat(WRONG_VLAN) \
    stat(ZERO_SRC_MAC) \
    stat(SRC_DISCARD) \
    stat(STATION_MOVE) \
    stat(NEW_HOST) \
    stat(ARP_OFFLOAD_TRAP) \
    stat(ARP_OFFLOAD) \
    stat(DHCP_OFFLOAD) \
    stat(DESTINATION_LOOKUP_FAILURE) \
    stat(DST_DISCARD) \
    stat(FLOATING_IP_FORWARD) \
    stat(FLOATING_IP_REVERSE) \
    stat(EMPTY_LAG) \
    stat(L3) \
    stat(BAD_TTL) \
    stat(L3_DROP) \
    stat(L3_NULL_ROUTE) \
    stat(L3_MISS) \
    stat(EMPTY_ECMP) \
    stat(DEBUG_REDIRECT) \
    stat(DEBUG_DROP) \
    stat(EGRESS_BAD_VLAN) \
    stat(PACKET_OF_DEATH) \
    stat(PIM_OFFLOAD)

enum pipeline_bvs_stats {
#define stat(name) PIPELINE_BVS_STATS_ ## name,
    PIPELINE_STATS
#undef stat
    PIPELINE_BVS_STATS_COUNT,
};

/* Assumes struct ctx *ctx */
#define PIPELINE_STAT(name) \
    pipeline_add_stats(ctx->stats, &pipeline_bvs_stats[PIPELINE_BVS_STATS_ ## name]);

extern struct stats_handle pipeline_bvs_stats[PIPELINE_BVS_STATS_COUNT];

void pipeline_bvs_stats_init(void);
void pipeline_bvs_stats_finish(void);

#endif
