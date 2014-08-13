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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inband/inband.h>
#include <assert.h>
#include <arpa/inet.h>
#include <AIM/aim.h>
#include <loci/loci.h>
#include <indigo/of_state_manager.h>

static uint8_t lldp1[] = {
    // Destination MAC
    0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
    // Source MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

static indigo_core_packet_in_listener_f listener = NULL;

static void
packet_in(const uint8_t *data, int length, of_port_no_t in_port)
{
    of_packet_in_t *obj = of_packet_in_new(OF_VERSION_1_3);
    of_match_t match = { 0 };
    match.version = OF_VERSION_1_3;
    match.fields.in_port = in_port;
    OF_MATCH_MASK_IN_PORT_EXACT_SET(&match);
    AIM_TRUE_OR_DIE(of_packet_in_match_set(obj, &match) == 0);
    of_octets_t octets = { .data = (uint8_t *)data, .bytes = length };
    AIM_TRUE_OR_DIE(of_packet_in_data_set(obj, &octets) == 0);
    indigo_core_listener_result_t result = listener(obj);
    AIM_ASSERT(result == INDIGO_CORE_LISTENER_RESULT_PASS);
    of_object_delete(obj);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    inband_init();

    assert(listener != NULL);

    packet_in(lldp1, sizeof(lldp1), 1);

    return 0;
}

/* OFStateManager stubs */

indigo_error_t
indigo_core_packet_in_listener_register(indigo_core_packet_in_listener_f fn)
{
    assert(listener == NULL);
    listener = fn;
    return INDIGO_ERROR_NONE;
}
