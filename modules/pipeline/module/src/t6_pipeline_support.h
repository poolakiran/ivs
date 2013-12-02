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

#ifndef OVSDRIVER_PIPELINE_SUPPORT_H
#define OVSDRIVER_PIPELINE_SUPPORT_H

#include <stdlib.h>
#include <arpa/inet.h>

#include <xbuf/xbuf.h>
#include <ivs/ivs.h>
#include <ivs/actions.h>
#include <loci/loci.h>
#include <indigo/error.h>
#include <pipeline/pipeline.h>

#define UNUSED __attribute__((unused))

enum bsn_pktin_reason {
    BSN_PACKET_IN_REASON_NEW_HOST = 128,
    BSN_PACKET_IN_REASON_STATION_MOVE = 129,
    BSN_PACKET_IN_REASON_BAD_VLAN = 130,
    BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE = 131,
    BSN_PACKET_IN_REASON_NO_ROUTE = 132,
};

static void
pktin(struct pipeline_result *result, uint8_t reason)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_CONTROLLER,
                     &reason, sizeof(reason));
}

static void
output(struct pipeline_result *result, uint32_t port_no)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_OUTPUT,
                     &port_no, sizeof(port_no));
}

static void UNUSED
push_vlan(struct pipeline_result *result, uint16_t ethertype)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_PUSH_VLAN,
                     &ethertype, sizeof(ethertype));
}

static void UNUSED
pop_vlan(struct pipeline_result *result)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_POP_VLAN, NULL, 0);
}

static void UNUSED
set_vlan_vid(struct pipeline_result *result, uint16_t vlan_vid)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_SET_VLAN_VID,
                     &vlan_vid, sizeof(vlan_vid));
}

static void UNUSED
set_vlan_pcp(struct pipeline_result *result, uint8_t vlan_pcp)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_SET_VLAN_PCP,
                     &vlan_pcp, sizeof(vlan_pcp));
}

#endif
