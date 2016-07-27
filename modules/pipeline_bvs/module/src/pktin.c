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

#include "pipeline_bvs_int.h"
#include "packet_of_death.h"
#include <inband/inband.h>
#include <cdpa/cdpa.h>
#include <lldpa/lldpa.h>
#include <lacpa/lacpa.h>
#include <arpa/arpa.h>
#include <icmpa/icmpa.h>
#include <dhcpra/dhcpra.h>
#include <router_ip_table/router_ip_table.h>
#include <indigo/port_manager.h>
#include <igmpa/igmpa.h>
#include <icmpv6/icmpv6.h>

DEBUG_COUNTER(pktin, "pipeline_bvs.pktin",
              "Received packet-in message from the kernel");
DEBUG_COUNTER(ctrl_pktin, "pipeline_bvs.pktin.controller",
              "Pktin's passed directly to the controller");
DEBUG_COUNTER(packet_of_death_pktin, "pipeline_bvs.pktin.packet_of_death",
              "Packet of death recv'd");
DEBUG_COUNTER(sflow_pktin, "pipeline_bvs.pktin.sflow",
              "Sflow sampled pktin's recv'd");
DEBUG_COUNTER(pktin_parse_error, "pipeline_bvs.pktin.parse_error",
              "Error while parsing packet-in");

struct pipeline_bvs_port_pktin_socket {
    struct ind_ovs_pktin_socket pktin_soc;
    bool in_use;
};

static struct pipeline_bvs_port_pktin_socket port_pktin_soc[SLSHARED_CONFIG_OF_PORT_MAX+1];

static struct ind_ovs_pktin_socket sflow_pktin_soc;
static struct ind_ovs_pktin_socket debug_acl_pktin_soc;

static const of_mac_addr_t cdp_mac = { { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc } };

/*
 * Returns true if a given port is ephemeral, else returns false
 */
static bool
is_ephemeral(uint32_t port)
{
    return (port >= 32768 && port <= 61000);
}

/*
 * Returns the pktin socket based on the given the pktin flags
 */
struct ind_ovs_pktin_socket *
pipeline_bvs_get_pktin_socket(of_port_no_t port_no, uint64_t userdata)
{
    uint64_t metadata = IVS_PKTIN_METADATA(userdata);

    if (metadata & OFP_BSN_PKTIN_FLAG_SFLOW) {
        return &sflow_pktin_soc;
    } else if ((metadata ^ OFP_BSN_PKTIN_FLAG_INGRESS_ACL) == 0 ||
        (metadata ^ OFP_BSN_PKTIN_FLAG_DEBUG) == 0) {
        return &debug_acl_pktin_soc;
    }

    AIM_ASSERT(port_no <= SLSHARED_CONFIG_OF_PORT_MAX,
               "Port %u out of range", port_no);

    if (port_no > SLSHARED_CONFIG_OF_PORT_MAX || !port_pktin_soc[port_no].in_use) {
        port_no = 0;
    }

    return &port_pktin_soc[port_no].pktin_soc;
}

/*
 * Process below pktin's:
 * - PDU's (LLDP, LACP, CDP)
 * - Switch agent pktins (ICMP, ARP, DHCP)
 * - Packet of Death
 * - Controller pktin's (New host, Station move)
 */
static void
process_port_pktin(uint8_t *data, unsigned int len,
                   uint8_t reason, uint64_t metadata,
                   struct ind_ovs_parsed_key *pkey)
{
    of_octets_t octets = { .data = data, .bytes = len };
    debug_counter_inc(&pktin);

    if (reason == OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH) {
        debug_counter_inc(&packet_of_death_pktin);
        pipeline_bvs_process_packet_of_death(&octets);
        return;
    }

    /* Identify if the packet-in needs to go to the controller before parsing */
    if (metadata & OFP_BSN_PKTIN_FLAG_STATION_MOVE ||
        metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST ||
        metadata & OFP_BSN_PKTIN_FLAG_ARP_CACHE) {
        goto send_to_controller;
    }

    ppe_packet_t ppep;
    ppe_packet_init(&ppep, data, len);
    if (ppe_parse(&ppep) < 0) {
        debug_counter_inc(&pktin_parse_error);
        return;
    }

    /*
     * Identify the packet-in based on header type
     *
     * Echo requests/traceroute destined to VRouter will be
     * consumed by the ICMP agent on the switch.
     * But L3 destination miss needs to be processed
     * before ICMP Echo requests.
     *
     * If these pktin's also have ttl expired, we dont need to respond
     * with icmp ttl expired msg to the original source,
     * since echo/traceroute response will take precedence.
     */
    indigo_core_listener_result_t result = INDIGO_CORE_LISTENER_RESULT_PASS;
    if (!memcmp(data, cdp_mac.addr, OF_MAC_ADDR_BYTES)) {
        result = cdpa_receive_packet(&octets, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_LLDP)) {
        result = lldpa_receive_packet(&octets, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_LACP)) {
        result = lacpa_receive_packet (&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_DHCP)) {
        result = dhcpra_receive_packet(&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_IGMP)) {
        result = igmpa_receive_pkt(&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_ICMPV6)) {
        result = icmpv6_receive_packet(&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_ARP)) {
        bool check_source = (metadata & OFP_BSN_PKTIN_FLAG_ARP) != 0;
        result = arpa_receive_packet(&ppep, pkey->in_port, check_source);
    } else if (ppe_header_get(&ppep, PPE_HEADER_IP4) &&
            (metadata & OFP_BSN_PKTIN_FLAG_L3_MISS)) {
        result = icmpa_send(&ppep, pkey->in_port, 3, 0);
    } else if (ppe_header_get(&ppep, PPE_HEADER_ICMP)) {
        result = icmpa_reply(&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_UDP) &&
        ppe_header_get(&ppep, PPE_HEADER_IP4)) {

        /*
         * To handle traceroute, we need to check for
         * a) UDP Packet
         * b) dest IP is Vrouter IP
         * c) UDP src and dest ports are ephemeral
         */
        uint32_t dest_ip, src_port, dest_port;
        ppe_field_get(&ppep, PPE_FIELD_IP4_DST_ADDR, &dest_ip);
        ppe_field_get(&ppep, PPE_FIELD_UDP_SRC_PORT, &src_port);
        ppe_field_get(&ppep, PPE_FIELD_UDP_DST_PORT, &dest_port);

        if (router_ip_check(dest_ip) && is_ephemeral(src_port) &&
            is_ephemeral(dest_port)) {
            result = icmpa_send(&ppep, pkey->in_port, 3, 3);
        }
    }

    /*
     * Identify if the packet-in has debug/acl flag set
     * Debug/ACL packet-in's should always go the controller
     */
    bool debug_acl_flag = metadata & (OFP_BSN_PKTIN_FLAG_INGRESS_ACL|OFP_BSN_PKTIN_FLAG_DEBUG);

    if (result == INDIGO_CORE_LISTENER_RESULT_DROP) {
        if (debug_acl_flag) {
            goto send_to_controller;
        } else {
            return;
        }
    }

    /*
     * Packet-in's passed by ICMP agent should later be
     * checked for ttl expired reason
     */
    if (ppe_header_get(&ppep, PPE_HEADER_IP4) &&
            (metadata & OFP_BSN_PKTIN_FLAG_TTL_EXPIRED)) {
        result = icmpa_send(&ppep, pkey->in_port, 11, 0);
    }

    if (result == INDIGO_CORE_LISTENER_RESULT_DROP && !debug_acl_flag) {
        return;
    }

send_to_controller:
    debug_counter_inc(&ctrl_pktin);
    ind_ovs_pktin(pkey->in_port, data, len, reason, metadata, pkey);
    return;
}

/*
 * Process sampled pktin's and send them directly to the sflow agent
 * Sflow samples are never sent to the controller
 */
static void
process_sflow_pktin(uint8_t *data, unsigned int len,
                    uint8_t reason, uint64_t metadata,
                    struct ind_ovs_parsed_key *pkey)
{
    debug_counter_inc(&sflow_pktin);

    ppe_packet_t ppep;
    ppe_packet_init(&ppep, data, len);
    if (ppe_parse(&ppep) < 0) {
        debug_counter_inc(&pktin_parse_error);
        return;
    }

    sflowa_receive_packet(&ppep, pkey->in_port);
}

void
pipeline_bvs_pktin_socket_register()
{
    /* Register the sflow pktin socket */
    ind_ovs_pktin_socket_register(&sflow_pktin_soc,
                                  process_sflow_pktin,
                                  GLOBAL_PKTIN_INTERVAL, PKTIN_BURST);

    /* Register the debug/acl pktin socket */
    ind_ovs_pktin_socket_register(&debug_acl_pktin_soc, NULL,
                                  GLOBAL_PKTIN_INTERVAL, PKTIN_BURST);

    /* Register port pktin sockets */
    indigo_port_info_t *port_list, *port_info;
    if (indigo_port_interface_list(&port_list) < 0) {
        AIM_LOG_ERROR("Failed to retrieve port list");
        return;
    }

    pipeline_bvs_port_pktin_socket_register(0);

    for (port_info = port_list; port_info; port_info = port_info->next) {
        if (port_info->of_port <= SLSHARED_CONFIG_OF_PORT_MAX) {
            pipeline_bvs_port_pktin_socket_register(port_info->of_port);
        }
    }

    indigo_port_interface_list_destroy(port_list);
}

void
pipeline_bvs_pktin_socket_unregister()
{
    /* Unregister the sflow pktin socket */
    ind_ovs_pktin_socket_unregister(&sflow_pktin_soc);

    /* Unregister the debug/acl pktin socket */
    ind_ovs_pktin_socket_unregister(&debug_acl_pktin_soc);

    /* Unregister port pktin sockets */
    int i;
    for (i = 0; i <= SLSHARED_CONFIG_OF_PORT_MAX; i++) {
        pipeline_bvs_port_pktin_socket_unregister(i);
    }
}

void
pipeline_bvs_port_pktin_socket_register(of_port_no_t port_no)
{

    AIM_ASSERT(port_no <= SLSHARED_CONFIG_OF_PORT_MAX,
               "Port %u out of range", port_no);

    if (port_pktin_soc[port_no].in_use == true) {
        return;
    }

    /* Create pktin socket for this port */
    ind_ovs_pktin_socket_register(&port_pktin_soc[port_no].pktin_soc,
                                  process_port_pktin,
                                  PORT_PKTIN_INTERVAL, PKTIN_BURST);
    port_pktin_soc[port_no].in_use = true;
}

void pipeline_bvs_port_pktin_socket_unregister(of_port_no_t port_no)
{
    AIM_ASSERT(port_no <= SLSHARED_CONFIG_OF_PORT_MAX,
               "Port %u out of range", port_no);

    if (port_pktin_soc[port_no].in_use == false) {
        return;
    }

    ind_ovs_pktin_socket_unregister(&port_pktin_soc[port_no].pktin_soc);
    port_pktin_soc[port_no].in_use = false;
}
