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
#include <indigo/port_manager.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

static const uint8_t packet_of_death[] = {
    // Destination MAC
    0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
    // Source MAC
    0x5c, 0x16, 0xc7, 0xff, 0xff, 0x04,
    // LLDP Ether Type
    0x88, 0xcc,
    // Chassis ID
    0x02, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Port ID
    0x04, 0x04, 0x05, 0x61, 0x6c, 0x6c,
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

void
pipeline_bvs_process_packet_of_death(of_octets_t *data)
{
    if (data->bytes != sizeof(packet_of_death)
        || memcmp(data->data, packet_of_death, sizeof(packet_of_death))) {
        AIM_LOG_VERBOSE("Received malformed packet of death");
        return;
    }

    AIM_LOG_WARN("Received packet of death, shutting down all ports");

    indigo_port_info_t *port_list, *port_info;
    if (indigo_port_interface_list(&port_list) < 0) {
        AIM_LOG_VERBOSE("Failed to retrieve port list");
        return;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    if (sock < 0) {
        return;
    }

    for (port_info = port_list; port_info; port_info = port_info->next) {
        struct ifreq req;
        strncpy(req.ifr_name, port_info->port_name, sizeof(req.ifr_name));

        /*
         * Execute the SIOCGIFFLAGS ioctl on the given interface,
         * to get the current ifflags.
         */
        if (ioctl(sock, SIOCGIFFLAGS, &req) < 0) {
            /* Not a netdev, continue */
            continue;
        } else {
            req.ifr_flags &= ~IFF_UP;

            /*
            * Execute the SIOCSIFFLAGS ioctl on the given interface,
            * to set the new ifflags.
            */
            if (ioctl(sock, SIOCSIFFLAGS, &req) < 0) {
                AIM_LOG_VERBOSE("Failed to set ifflags for port %u: %s",
                                port_info->of_port, strerror(errno));
                goto cleanup;
            }
        }
    }

    ind_ovs_barrier_defer_revalidation(-1);

cleanup:
    indigo_port_interface_list_destroy(port_list);
    close(sock);
}
