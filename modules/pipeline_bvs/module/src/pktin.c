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
#include <lldpa/lldpa.h>
#include <lacpa/lacpa.h>
#include <arpa/arpa.h>
#include <icmpa/icmpa.h>
#include <dhcpra/dhcpra.h>
#include <router_ip_table/router_ip_table.h>

DEBUG_COUNTER(ctrl_pktin, "pipeline_bvs.pktin.controller",
              "Pktin's passed directly to the controller");
DEBUG_COUNTER(packet_of_death_pktin, "pipeline_bvs.pktin.packet_of_death",
              "Packet of death recv'd");
DEBUG_COUNTER(sflow_pktin, "pipeline_bvs.pktin.sflow",
              "Sflow sampled pktin's recv'd");
DEBUG_COUNTER(pktin_parse_error, "pipeline_bvs.pktin.parse_error",
              "Error while parsing packet-in");

/*
 * Returns true if a given port is ephemeral, else returns false
 */
static bool
is_ephemeral(uint32_t port)
{
    return (port >= 32768 && port <= 61000);
}

/*
 * Process below pktin's:
 * - PDU's (LLDP, LACP, CDP)
 * - Switch agent pktins (ICMP, ARP, DHCP)
 * - Packet of Death
 * - Controller pktin's (New host, Station move)
 */
void process_port_pktin(uint8_t *data, unsigned int len,
                        uint8_t reason, uint64_t metadata,
                        struct ind_ovs_parsed_key *pkey)
{
    of_octets_t octets = { .data = data, .bytes = len };

    if (reason == OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH) {
        debug_counter_inc(&packet_of_death_pktin);
        process_packet_of_death(&octets);
        return;
    }

    if (metadata & OFP_BSN_PKTIN_FLAG_STATION_MOVE ||
        metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST ||
        metadata & OFP_BSN_PKTIN_FLAG_ARP_CACHE) {
        debug_counter_inc(&ctrl_pktin);
        ind_ovs_pktin(pkey->in_port, data, len, reason, metadata, pkey);
        return;
    }

    ppe_packet_t ppep;
    ppe_packet_init(&ppep, data, len);
    if (ppe_parse(&ppep) < 0) {
        debug_counter_inc(&pktin_parse_error);
        return;
    }

    indigo_core_listener_result_t result = INDIGO_CORE_LISTENER_RESULT_PASS;
    if (ppe_header_get(&ppep, PPE_HEADER_LLDP)) {
        inband_receive_packet(&ppep, pkey->in_port);
        result = lldpa_receive_packet(&octets, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_LACP)) {
        result = lacpa_receive_packet (&ppep, pkey->in_port);
    } else if (ppe_header_get(&ppep, PPE_HEADER_DHCP)) {
        result = dhcpra_receive_packet(&ppep, pkey->in_port);
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

    if (result == INDIGO_CORE_LISTENER_RESULT_DROP) {
        return;
    }

    if (metadata & (OFP_BSN_PKTIN_FLAG_ARP|OFP_BSN_PKTIN_FLAG_ARP_TARGET)) {
        bool check_source = (metadata & OFP_BSN_PKTIN_FLAG_ARP) != 0;
        result = arpa_receive_packet(&ppep, pkey->in_port, check_source);
    } else if (metadata & OFP_BSN_PKTIN_FLAG_L3_MISS) {
        result = icmpa_send(&ppep, pkey->in_port, 3, 0);
    } else if (metadata & OFP_BSN_PKTIN_FLAG_TTL_EXPIRED) {
        result = icmpa_send(&ppep, pkey->in_port, 11, 0);
    }

    if (result != INDIGO_CORE_LISTENER_RESULT_DROP) {
        debug_counter_inc(&ctrl_pktin);
        ind_ovs_pktin(pkey->in_port, data, len, reason, metadata, pkey);
    }
}

/*
 * Process sampled pktin's and send them directly to the sflow agent
 * Sflow samples are never sent to the controller
 */
void process_sflow_pktin(uint8_t *data, unsigned int len,
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
