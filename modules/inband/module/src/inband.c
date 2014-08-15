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

/*
 * This module configures controller connections in response to LLDP
 * packet-ins received on an uplink port. It looks for the standard
 * "management address" TLV and adds a controller connection for each
 * one.
 *
 * An LLDP packet without any management addresses will remove all controllers.
 *
 * The set of controllers configured by this module is independent of those
 * configured with the command line and config file. It's expected that we
 * won't use those other mechanisms when using this module.
 */

#include <AIM/aim.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "inband_int.h"
#include "inband_log.h"
#include <indigo/of_connection_manager.h>
#include <indigo/of_state_manager.h>
#include <PPE/ppe.h>
#include <debug_counter/debug_counter.h>

#define LLDP_TLV_MANAGEMENT_ADDRESS 8
#define LLDP_ADDRESS_FAMILY_IPV4 1
#define LLDP_ADDRESS_FAMILY_IPV6 2

#define MAX_INBAND_CONTROLLERS 4

struct lldp_tlv {
    uint8_t type;
    uint32_t oui;
    uint8_t subtype;
    const uint8_t *payload;
    uint16_t payload_length;
};

struct inband_controller {
    indigo_controller_id_t id;
    indigo_cxn_protocol_params_t protocol_params;
};

static void synchronize_controllers(
    struct inband_controller *new_controllers,
    int num_new_controllers);

/* HACK not in IVS yet */
bool ind_ovs_uplink_check(of_port_no_t port);

static struct inband_controller controllers[MAX_INBAND_CONTROLLERS];
static int num_controllers = 0;

/* Copied from IVS main.c */
static indigo_cxn_config_params_t cxn_config_params = {
    .version = OF_VERSION_1_3,
    .cxn_priority = 0,
    .local = false,
    .listen = false,
    .periodic_echo_ms = 2000,
    .reset_echo_count = 3,
};

static debug_counter_t received_uplink_lldp;
static debug_counter_t invalid_tlv;
static debug_counter_t invalid_management_tlv;
static debug_counter_t controller_add_failed;

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
        debug_counter_inc(&invalid_tlv);
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
        debug_counter_inc(&invalid_tlv);
        return false;
    }

    tlv->payload = data + 2;
    tlv->payload_length = payload_length;

    if (tlv->type == 127) {
        if (payload_length < 4) {
            AIM_LOG_WARN("Not enough payload bytes for an LLDP organizational TLV");
            debug_counter_inc(&invalid_tlv);
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

    if (!ind_ovs_uplink_check(match.fields.in_port)) {
        AIM_LOG_TRACE("Not received on an uplink port");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

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

    debug_counter_inc(&received_uplink_lldp);

    AIM_LOG_VERBOSE("Parsing LLDP packet");

    struct inband_controller new_controllers[MAX_INBAND_CONTROLLERS];
    int num_new_controllers = 0;

    struct lldp_tlv tlv;
    int remain = octets.bytes - (header - octets.data);
    const uint8_t *pos = header;
    while (lldp_parse_tlv(&pos, &remain, &tlv)) {
        AIM_LOG_TRACE("Found tlv type=%u oui=%u subtype=%u payload_length=%u", tlv.type, tlv.oui, tlv.subtype, tlv.payload_length);
        if (tlv.type == LLDP_TLV_MANAGEMENT_ADDRESS) {
            AIM_LOG_TRACE("Found management address TLV");

            if (tlv.payload_length < 9 /* from 802.1ab spec */) {
                AIM_LOG_WARN("Management address TLV too short");
                debug_counter_inc(&invalid_management_tlv);
                continue;
            }

            int addr_len = tlv.payload[0];
            int addr_type = tlv.payload[1];

            if (num_controllers >= MAX_INBAND_CONTROLLERS) {
                AIM_LOG_WARN("Too many controllers in LLDP");
                debug_counter_inc(&invalid_management_tlv);
                continue;
            }

            struct inband_controller *new_controller = &new_controllers[num_new_controllers];
            memset(new_controller, 0, sizeof(*new_controller));

            if (addr_type == LLDP_ADDRESS_FAMILY_IPV4) {
                if (addr_len != sizeof(of_ipv4_t)) {
                    AIM_LOG_WARN("Invalid IPv4 address length in management address TLV");
                    debug_counter_inc(&invalid_management_tlv);
                    continue;
                }

                struct in_addr in = { *(uint32_t *)&tlv.payload[2] };
                AIM_LOG_VERBOSE("Controller address: %{ipv4a}", ntohl(in.s_addr));

                indigo_cxn_params_tcp_over_ipv4_t *proto = &new_controller->protocol_params.tcp_over_ipv4;
                proto->protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV4;
                strcpy(proto->controller_ip, inet_ntoa(in));
                proto->controller_port = 6653;
            } else {
                AIM_LOG_WARN("Ignoring management address TLV with unsupported address type %u", addr_type);
                debug_counter_inc(&invalid_management_tlv);
                continue;
            }

            num_new_controllers++;
        }
    }

    synchronize_controllers(new_controllers, num_new_controllers);

    return INDIGO_CORE_LISTENER_RESULT_PASS;
}

static void
synchronize_controllers(struct inband_controller *new_controllers, int num_new_controllers)
{
    int i, j;

    /* Remove old controllers
     *
     * For each old controller, search the list of new controllers to find
     * a match. If no match is found, remove it.
     */
    for (i = 0; i < num_controllers; i++) {
        struct inband_controller *old = &controllers[i];
        bool found = false;

        for (j = 0; j < num_new_controllers; j++) {
            struct inband_controller *new = &new_controllers[j];
            if (!memcmp(&old->protocol_params, &new->protocol_params, sizeof(old->protocol_params))) {
                found = true;
                break;
            }
        }

        if (!found) {
            (void) indigo_controller_remove(old->id);

            /* Copy the last element to this index and decrement the size */
            controllers[i] = controllers[--num_controllers];

            /* Need to redo this index */
            i--;
        }
    }

    /*
     * Add new controllers
     *
     * For each new controller, search the list of old controllers to find
     * a match. If no match is found, add it.
     */
    for (i = 0; i < num_new_controllers; i++) {
        struct inband_controller *new = &new_controllers[i];
        bool found = false;

        for (j = 0; j < num_controllers; j++) {
            struct inband_controller *old = &controllers[j];
            if (!memcmp(&old->protocol_params, &new->protocol_params, sizeof(old->protocol_params))) {
                found = true;
                break;
            }
        }

        if (!found) {
            indigo_error_t rv;
            AIM_ASSERT(num_controllers < MAX_INBAND_CONTROLLERS);
            if ((rv = indigo_controller_add(&new->protocol_params, &cxn_config_params, &new->id)) < 0) {
                AIM_LOG_ERROR("Failed to add controller from LLDP: %s", indigo_strerror(rv));
                debug_counter_inc(&controller_add_failed);
            } else {
                /* Append to the controllers list */
                controllers[num_controllers++] = *new;
            }
        }
    }
}

void
inband_init(void)
{
    (void) indigo_core_packet_in_listener_register(pktin_listener);

    debug_counter_register(&received_uplink_lldp, "inband.received_uplink_lldp",
                           "Received an LLDP on an uplink port");
    debug_counter_register(&invalid_tlv, "inband.invalid_tlv",
                           "Found an invalid LLDP TLV");
    debug_counter_register(&invalid_management_tlv, "inband.invalid_management_tlv",
                           "Found an invalid LLDP Management Address TLV");
    debug_counter_register(&controller_add_failed, "inband.controller_add_failed",
                           "Failed to add a controller specified in a LLDP");
}

void
__inband_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
