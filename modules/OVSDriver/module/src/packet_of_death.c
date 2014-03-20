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

#include "ovs_driver_int.h"
#include <indigo/of_state_manager.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

static const uint8_t packet_of_death[] = {
    // Destination MAC
    0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
    // Source MAC
    0x5C, 0x16, 0xC7, 0xFF, 0xFF, 0x04,
    // LLDP Ether Type
    0x88, 0xcc,
    // Chassis ID
    0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Port ID
    0x04, 0x03, 0x02, 0xff, 0xfc,
    // TTL
    0x06, 0x02, 0x00, 0x78,
    // System Name
    0x0a, 0x0a, 0x50, 0x4F, 0x44, 0x2D, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    // System Desc
    0x0c, 0x11, 0x35, 0x63, 0x3A, 0x31, 0x36, 0x3A, 0x63, 0x37, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x31,
    // Switch Type
    0xfe, 0x05, 0x00, 0x26, 0xe1, 0x01, 0x01,
    // Direction TLV
    0xfe, 0x05, 0x00, 0x26, 0xe1, 0x03, 0x01,
    // Controller ID TLV
    0xfe, 0x10, 0x00, 0x26, 0xe1, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // End of LLDP PDU
    0x00, 0x00
};

static indigo_core_listener_result_t
ind_ovs_packet_of_death_listener(of_packet_in_t *msg)
{
    uint8_t reason;
    of_packet_in_reason_get(msg, &reason);
    if (reason != OF_PACKET_IN_REASON_BSN_PACKET_OF_DEATH) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_octets_t data;
    of_packet_in_data_get(msg, &data);
    if (data.bytes != sizeof(packet_of_death)
            || memcmp(data.data, packet_of_death, sizeof(packet_of_death))) {
        AIM_LOG_VERBOSE("Received malformed packet of death, dropping");
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    AIM_LOG_WARN("Received packet of death, shutting down all ports");

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port) {
            port->admin_down = true;
            port->ifflags &= ~IFF_UP;
            (void) ind_ovs_set_interface_flags(port->ifname, port->ifflags);
        }
    }

    ind_ovs_kflow_invalidate_all();

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

void
ind_ovs_packet_of_death_init(void)
{
    indigo_core_packet_in_listener_register(ind_ovs_packet_of_death_listener);
}
