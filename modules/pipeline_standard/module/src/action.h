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

#ifndef PIPELINE_STANDARD_ACTION_H
#define PIPELINE_STANDARD_ACTION_H

#include <ivs/ivs.h>
#include <xbuf/xbuf.h>
#include <loci/loci.h>
#include <indigo/error.h>
#include <action/action.h>

/*
 * IVS actions
 *
 * These actions are more efficient for the upcall processing code to parse
 * than the LOCI of_list_action_t. It also helps to abstract some of the
 * differences between OpenFlow 1.0 and 1.3.
 */

enum {
    IND_OVS_ACTION_OUTPUT, /* of_port_no_t */
    IND_OVS_ACTION_CONTROLLER, /* uint64_t userdata (reason in bottom 8 bits, metadata in top 56 bits) */
    IND_OVS_ACTION_LOCAL,
    IND_OVS_ACTION_IN_PORT,
    IND_OVS_ACTION_SET_ETH_DST, /* of_mac_addr_t */
    IND_OVS_ACTION_SET_ETH_SRC, /* of_mac_addr_t */
    IND_OVS_ACTION_SET_IPV4_DST, /* uint32_t */
    IND_OVS_ACTION_SET_IPV4_SRC, /* uint32_t */
    IND_OVS_ACTION_SET_IP_DSCP, /* uint8_t , Upper 6 bits */
    IND_OVS_ACTION_SET_IP_ECN,  /* uint8_t , Lower 2 bits */
    IND_OVS_ACTION_SET_TCP_DST, /* uint16_t */
    IND_OVS_ACTION_SET_TCP_SRC, /* uint16_t */
    IND_OVS_ACTION_SET_UDP_DST, /* uint16_t */
    IND_OVS_ACTION_SET_UDP_SRC, /* uint16_t */
    IND_OVS_ACTION_SET_TP_DST,  /* uint16_t */
    IND_OVS_ACTION_SET_TP_SRC,  /* uint16_t */
    IND_OVS_ACTION_SET_VLAN_VID, /* uint16_t */
    IND_OVS_ACTION_SET_VLAN_PCP, /* uint8_t */
    IND_OVS_ACTION_POP_VLAN,
    IND_OVS_ACTION_PUSH_VLAN,    /* uint16_t */
    IND_OVS_ACTION_DEC_NW_TTL,
    IND_OVS_ACTION_SET_NW_TTL,   /* uint8_t */
    IND_OVS_ACTION_SET_IPV6_DST,    /* of_ipv6_t */
    IND_OVS_ACTION_SET_IPV6_SRC,    /* of_ipv6_t */
    IND_OVS_ACTION_SET_IPV6_FLABEL, /* uint32_t */
    IND_OVS_ACTION_SET_PRIORITY, /* uint32_t */
    IND_OVS_ACTION_GROUP, /* struct group * */
};

/* Translate OpenFlow actions into IVS actions */
indigo_error_t pipeline_standard_translate_openflow_actions(of_list_action_t *actions, struct xbuf *xbuf, bool table_miss);

/* Release resources acquired during OpenFlow action translation */
void pipeline_standard_cleanup_actions(struct xbuf *actions);

/* Translate IVS actions into OVS actions */
void pipeline_standard_translate_actions(
    struct action_context *ctx, struct xbuf *actions,
    uint32_t hash, struct xbuf *stats);

/* Netlink socket to be used for receiving pktin's */
extern struct ind_ovs_pktin_socket pktin_soc;

#endif
