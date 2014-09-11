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
#include <AIM/aim_log.h>
#include <loci/loci.h>
#include <indigo/of_connection_manager.h>
#include <indigo/of_state_manager.h>
#include <indigo/port_manager.h>

enum listener_result_assertion {
    PASS = INDIGO_CORE_LISTENER_RESULT_PASS,
    DROP = INDIGO_CORE_LISTENER_RESULT_DROP,
    DONTCARE,
};

static const uint8_t lldp_prefix[] = {
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
};

static const uint8_t expected_reply[] = {
    // Destination MAC
    0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e,
    // Source MAC
    0x5c, 0x16, 0xc7, 0xff, 0xff, 0x08,
    // LLDP Ether Type
    0x88, 0xcc,
    // Chassis ID
    0x02, 0x07, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    // Port ID
    0x04, 0x05, 0x05, 'e', 't', 'h', '0',
    // TTL
    0x06, 0x02, 0x00, 0x78,
    // System Name
    0x0a, 0x08, 'h', 'o', 's', 't', 'n', 'a', 'm', 'e',
    // System Desc
    0x0c, 0x03, 'i', 'v', 's',
};

static indigo_port_info_t port_info[] = {
    { &port_info[1], "eth0", 1 },
    { &port_info[2], "eth1", 2 },
    { NULL, "eth2", 3 },
};

static indigo_core_packet_in_listener_f listener = NULL;
static const char *expected_adds[32], *expected_removes[32];
static int num_expected_adds, num_expected_removes;
static const char *controller_ips[1024];
static int next_controller_id;
static bool disable_expectations;

static void
packet_in(const uint8_t *data, int length,
          of_port_no_t in_port,
          enum listener_result_assertion expect)
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
    if (expect != DONTCARE) {
        AIM_ASSERT(expect == (int)result);
    }
    of_object_delete(obj);
}

/*
 * Management address TLV payload (see 802.1AB spec)
 *
 * - Address length (1 byte)
 * - Address type (1 byte)
 *   - ipv4=1
 *   - ipv6=2
 * - Management address (variable length)
 * - Interface number subtype (1 byte)
 *   - unknown=1
 * - Interface number (4 bytes)
 * - OID length (1 byte)
 * - OID (variable length)
 */

static int
append_management_address_tlv(uint8_t *dest, const char *ip)
{
    int i = 0;
    dest[i++] = 0x10; /* type */
    dest[i++] = 0x00; /* length placeholder */
    if (!strcmp(ip, "invalid-ipv4-length")) {
        dest[i++] = 0x03; /* address length */
        dest[i++] = 0x01; /* address type */
        dest[i++] = 0x55; /* address */
        dest[i++] = 0x55; /* address */
    } else if (!strcmp(ip, "unsupported-address-type")) {
        dest[i++] = 0x05; /* address length */
        dest[i++] = 0x88; /* address type */
        *(uint32_t *)&dest[i] = htonl(0x12345678); i+=4; /* address */
    } else {
        dest[i++] = 0x05; /* address length */
        dest[i++] = 0x01; /* address type */
        *(uint32_t *)&dest[i] = inet_addr(ip); i+=4; /* address */
    }
    dest[i++] = 1; /* interface number subtype */
    *(uint32_t *)&dest[i] = htonl(0); i+=4; /* interface number */
    dest[i++] = 0; /* OID length */
    dest[1] = i - 2; /* length */
    return i;
}

static void
lldp_packet_in(of_port_no_t port,
               const char *controller1_ip,
               const char *controller2_ip,
               enum listener_result_assertion expect)
{
    static uint8_t data[1500];
    int offset = 0;

    memcpy(data, lldp_prefix, sizeof(lldp_prefix));
    offset += sizeof(lldp_prefix);

    if (controller1_ip) {
        offset += append_management_address_tlv(data + offset, controller1_ip);
    }

    if (controller2_ip) {
        offset += append_management_address_tlv(data + offset, controller2_ip);
    }

    /* End of LLDPDU */
    data[offset++] = 0;
    data[offset++] = 0;

    fprintf(stderr, "Sending LLDP with management IPs %s and %s\n", controller1_ip, controller2_ip);

    packet_in(data, offset, port, expect);
}

static void
expect_add(const char *ip)
{
    expected_adds[num_expected_adds++] = ip;
}

static void
expect_remove(const char *ip)
{
    expected_removes[num_expected_removes++] = ip;
}

static void
check_expectations(void)
{
    if (num_expected_adds > 0) {
        int i;
        for (i = 0; i < num_expected_adds; i++) {
            fprintf(stderr, "FAIL: Missing expected add of %s\n", expected_adds[i]);
        }
    }

    if (num_expected_removes > 0) {
        int i;
        for (i = 0; i < num_expected_removes; i++) {
            fprintf(stderr, "FAIL: Missing expected remove of %s\n", expected_removes[i]);
        }
    }

    AIM_ASSERT(num_expected_adds == 0);
    AIM_ASSERT(num_expected_removes == 0);
}

/* Put the inband module back in a state with no controllers */
static void
reset(void)
{
    disable_expectations = true;
    lldp_packet_in(1, NULL, NULL, PASS);
    disable_expectations = false;
    check_expectations();
}

static void
test_basic(void)
{
    fprintf(stderr, "Starting basic test\n");

    /* Add two controllers */
    expect_add("1.2.3.4");
    expect_add("5.6.7.8");
    lldp_packet_in(1, "1.2.3.4", "5.6.7.8", PASS);
    check_expectations();

    /* Same controllers, different order */
    lldp_packet_in(1, "5.6.7.8", "1.2.3.4", PASS);
    check_expectations();

    /* Replace one controller */
    expect_remove("5.6.7.8");
    expect_add("9.9.9.9");
    lldp_packet_in(1, "1.2.3.4", "9.9.9.9", PASS);
    check_expectations();

    /* Replace both controllers */
    expect_remove("1.2.3.4");
    expect_remove("9.9.9.9");
    expect_add("10.10.10.10");
    expect_add("11.11.11.11");
    lldp_packet_in(1, "10.10.10.10", "11.11.11.11", PASS);
    check_expectations();

    /* Remove a controller */
    expect_remove("10.10.10.10");
    lldp_packet_in(1, "11.11.11.11", NULL, PASS);
    check_expectations();

    /* Remove the last controller */
    expect_remove("11.11.11.11");
    lldp_packet_in(1, NULL, NULL, PASS);
    check_expectations();
}

static void
test_corrupt(void)
{
    static uint8_t data[1500];
    int offset = 0;

    fprintf(stderr, "Starting corruption test\n");
    reset();

    memcpy(data, lldp_prefix, sizeof(lldp_prefix));
    offset += sizeof(lldp_prefix);

    offset += append_management_address_tlv(data + offset, "1.2.3.4");
    offset += append_management_address_tlv(data + offset, "5.6.7.8");

    /* End of LLDPDU */
    data[offset++] = 0;
    data[offset++] = 0;

    disable_expectations = true;

    /* This test generates lots of warnings */
    aim_log_fid_set_all(AIM_LOG_FLAG_WARN, 0);

    /* Flip each bit and make sure the parser doesn't crash */
    int bit;
    for (bit = 0; bit < offset*8; bit++) {
        data[bit/8] ^= 1<<(bit %8);
        packet_in(data, offset, 1, DONTCARE);
        data[bit/8] ^= 1<<(bit %8);
    }

    /* Truncate the message and make sure the parser doesn't crash */
    int i;
    for (i = 0; i < offset; i++) {
        packet_in(data, i, 1, DONTCARE);
    }

    disable_expectations = false;
    aim_log_fid_set_all(AIM_LOG_FLAG_WARN, 1);
}

/*
 * We don't expect the controller to send these LLDPs, but nothing bad should
 * happen.
 */
static void
test_invalid(void)
{
    fprintf(stderr, "Starting invalid LLDP test\n");
    reset();

    /* Duplicate addresses */
    expect_add("1.2.3.4");
    lldp_packet_in(1, "1.2.3.4", "1.2.3.4", PASS);
    check_expectations();

    /* Same duplicate addresses */
    lldp_packet_in(1, "1.2.3.4", "1.2.3.4", PASS);
    check_expectations();

    /* Different duplicate addresses */
    expect_remove("1.2.3.4");
    expect_add("5.6.7.8");
    lldp_packet_in(1, "5.6.7.8", "5.6.7.8", PASS);
    check_expectations();

    /* Fail indigo_cxn_controller_add */
    lldp_packet_in(1, "0.0.0.0", "5.6.7.8", PASS);
    check_expectations();

    /* Invalid IP address length */
    lldp_packet_in(1, "invalid-ipv4-length", "5.6.7.8", PASS);
    check_expectations();

    /* Unsupported address type */
    lldp_packet_in(1, "unsupported-address-type", "5.6.7.8", PASS);
    check_expectations();

    /* Not from an uplink port */
    lldp_packet_in(2, "1.2.3.4", "5.6.7.8", PASS);
    check_expectations();
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    inband_init();

    assert(listener != NULL);

    test_basic();
    test_corrupt();
    test_invalid();

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

indigo_error_t
indigo_core_dpid_get(of_dpid_t *dpid)
{
    *dpid = 0xaabb010203040506;
    return INDIGO_ERROR_NONE;
}

/* OFConnectionManager stubs */

indigo_error_t
indigo_controller_add(
    indigo_cxn_protocol_params_t *protocol_params,
    indigo_cxn_config_params_t *config_params,
    indigo_controller_id_t *id)
{
    if (disable_expectations) {
        *id = 0;
        return INDIGO_ERROR_NONE;
    }

    AIM_ASSERT(protocol_params->header.protocol == INDIGO_CXN_PROTO_TCP_OVER_IPV4);
    const char *ip = protocol_params->tcp_over_ipv4.controller_ip;

    if (!strcmp(ip, "0.0.0.0")) {
        return INDIGO_ERROR_UNKNOWN;
    }

    int i;
    for (i = 0; i < num_expected_adds; i++) {
        if (!strcmp(expected_adds[i], ip)) {
            fprintf(stderr, "Received expected add of %s\n", ip);
            *id = next_controller_id++;
            controller_ips[*id] = strdup(ip);
            expected_adds[i] = expected_adds[num_expected_adds-1];
            expected_adds[--num_expected_adds] = NULL;
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_ASSERT(0, "Unexpected add of %s", ip);
}

indigo_error_t
indigo_controller_remove(indigo_controller_id_t id)
{
    if (disable_expectations) {
        return INDIGO_ERROR_NONE;
    }

    const char *ip = controller_ips[id];

    int i;
    for (i = 0; i < num_expected_removes; i++) {
        if (!strcmp(expected_removes[i], ip)) {
            fprintf(stderr, "Received expected remove of %s\n", ip);
            expected_removes[i] = expected_removes[num_expected_removes-1];
            expected_removes[--num_expected_removes] = NULL;
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_ASSERT(0, "Unexpected remove of %s", ip);
}

/* IVS stubs */

bool
ind_ovs_uplink_check(of_port_no_t port)
{
    if (port == 1) {
        return true;
    } else {
        return false;
    }
}

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *obj)
{
    of_octets_t data;
    of_packet_out_data_get(obj, &data);
    AIM_ASSERT(data.bytes = sizeof(expected_reply));
    AIM_ASSERT(!memcmp(data.data, expected_reply, data.bytes));
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_interface_list(indigo_port_info_t** list)
{
    *list = &port_info[0];
    return INDIGO_ERROR_NONE;
}

void
indigo_port_interface_list_destroy(indigo_port_info_t* list)
{
}

/* libc stubs */

int
gethostname(char *name, size_t len)
{
    strncpy(name, "hostname", len);
    return 0;
}