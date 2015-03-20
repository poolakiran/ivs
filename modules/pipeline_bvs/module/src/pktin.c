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

DEBUG_COUNTER(packet_of_death_pktin, "pipeline_bvs.pktin.packet_of_death",
              "Packet of death recv'd");
DEBUG_COUNTER(sflow_pktin, "pipeline_bvs.pktin.sflow",
              "Sflow sampled pktin's recv'd");
DEBUG_COUNTER(pktin_parse_error, "pipeline_bvs.pktin.parse_error",
              "Error while parsing packet-in");

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
