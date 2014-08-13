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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <AIM/aim.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "inband_int.h"
#include "inband_log.h"
#include <indigo/of_state_manager.h>
#include <PPE/ppe.h>

#define LLDP_TLV_MANAGEMENT_ADDRESS 8
#define LLDP_ADDRESS_FAMILY_IPV4 1
#define LLDP_ADDRESS_FAMILY_IPV6 2

struct lldp_tlv {
    uint8_t type;
    uint32_t oui;
    uint8_t subtype;
    const uint8_t *payload;
    uint16_t payload_length;
};

/*
 * Parse the LLDP TLV starting at *data_p. Returns true if parsing was
 * successful. *remain should be initialized with the number of bytes
 * available starting from *data_p. After each successful call this
 * function will update *data_p, *remain, and *tlv.
 */
static bool
lldp_parse_tlv(const uint8_t **data_p, int *remain, struct lldp_tlv *tlv)
{
    const uint8_t *data = *data_p;

    if (*remain < 2) {
        AIM_LOG_WARN("Not enough bytes remaining for an LLDP TLV");
        return false;
    }

    memset(tlv, 0, sizeof(*tlv));
    tlv->type = data[0] >> 1;
    int payload_length = ((data[0] & 1) << 8) | data[1];

    if (tlv->type == 0 && payload_length == 0) {
        /* End of LLDPDU */
        return false;
    }

    int total_length = payload_length + 2;
    if (total_length > *remain) {
        AIM_LOG_WARN("Invalid LLDP TLV length %d", total_length);
        return false;
    }

    tlv->payload = data + 2;
    tlv->payload_length = payload_length;

    if (tlv->type == 127) {
        if (payload_length < 4) {
            AIM_LOG_WARN("Not enough payload bytes for an LLDP organizational TLV");
            return false;
        }
        tlv->oui = (data[2] << 16) | (data[3] << 8) | data[4];
        tlv->subtype = data[5];
        tlv->payload += 4;
        tlv->payload_length -= 4;
    }

    *data_p += total_length;
    *remain -= total_length;
    assert(*remain >= 0);

    return true;
}

static indigo_core_listener_result_t
pktin_listener(of_packet_in_t *packet_in)
{
    if (packet_in->version != OF_VERSION_1_3) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_match_t match;
    if (of_packet_in_match_get(packet_in, &match) < 0) {
        AIM_LOG_ERROR("Failed to parse packet-in match");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /* TODO Check if the source port is an uplink */

    of_octets_t octets;
    of_packet_in_data_get(packet_in, &octets);

    /*
     * Identify if this is an LLDP Packet
     */
    ppe_packet_t ppep;
    ppe_packet_init(&ppep, octets.data, octets.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_WARN("Packet-in parsing failed");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    uint8_t *header;
    if ((header = ppe_header_get(&ppep, PPE_HEADER_LLDP)) == NULL) {
        AIM_LOG_VERBOSE("Not an LLDP packet");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    AIM_LOG_VERBOSE("Parsing LLDP packet");

    struct lldp_tlv tlv;
    int remain = octets.bytes - (header - octets.data);
    const uint8_t *pos = header;
    while (lldp_parse_tlv(&pos, &remain, &tlv)) {
        AIM_LOG_TRACE("Found tlv type=%u oui=%u subtype=%u payload_length=%u", tlv.type, tlv.oui, tlv.subtype, tlv.payload_length);
        if (tlv.type == LLDP_TLV_MANAGEMENT_ADDRESS) {
            AIM_LOG_TRACE("Found management address TLV");

            if (tlv.payload_length < 9 /* from 802.1ab spec */) {
                AIM_LOG_WARN("Management address TLV too short");
                continue;
            }

            int addr_len = tlv.payload[0];
            int addr_type = tlv.payload[1];
            if (addr_type == LLDP_ADDRESS_FAMILY_IPV4) {
                if (addr_len != sizeof(of_ipv4_t)) {
                    AIM_LOG_WARN("Invalid IPv4 address length in management address TLV");
                    continue;
                }
                uint32_t ipv4 = ntohl(*(uint32_t *)&tlv.payload[2]);
                AIM_LOG_VERBOSE("Controller address: %{ipv4a}", ipv4);
            } else {
                AIM_LOG_WARN("Ignoring management address TLV with unsupported address type %u", addr_type);
            }
        }
    }

    return INDIGO_CORE_LISTENER_RESULT_PASS;
}

void
inband_init(void)
{
    (void) indigo_core_packet_in_listener_register(pktin_listener);
}

void
__inband_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
