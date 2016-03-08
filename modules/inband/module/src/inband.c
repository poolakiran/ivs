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
#include <arpa/inet.h>
#include <unistd.h>
#include <indigo/of_connection_manager.h>
#include <indigo/of_state_manager.h>
#include <indigo/port_manager.h>
#include <PPE/ppe.h>
#include <debug_counter/debug_counter.h>
#include <slshared/slshared_config.h>
#include <slshared/slshared.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/addr.h>
#include <netlink/route/neighbour.h>
#include "inband_int.h"
#include "inband_log.h"
#include "lldp.h"

#define MAX_INBAND_CONTROLLERS 4

struct inband_controller {
    indigo_controller_id_t id;
    indigo_cxn_protocol_params_t protocol_params;
};

static void synchronize_controllers(
    struct inband_controller *new_controllers,
    int num_new_controllers);

static void add_neighbor_entry(struct inband_controller *ctrl);

/* HACK not in IVS yet */
bool ind_ovs_uplink_check(of_port_no_t port);

static void retarget_logger(void);
static void get_port_name(of_port_no_t port, indigo_port_name_t port_name);

static struct inband_controller controllers[MAX_INBAND_CONTROLLERS];
static int num_controllers = 0;
static const char *inband_interface_name = "inband";
static bool inband_tls_enabled;

/* Copied from IVS main.c */
static indigo_cxn_config_params_t cxn_config_params = {
    .version = OF_VERSION_1_4,
    .cxn_priority = 0,
    .local = false,
    .listen = false,
    .periodic_echo_ms = 2000,
    .reset_echo_count = 3,
};

static debug_counter_t received_uplink_lldp;
static debug_counter_t sent_lldp_reply;
static debug_counter_t invalid_management_tlv;
static debug_counter_t controller_add_failed;

void
inband_receive_packet(uint8_t *data, unsigned int len, of_port_no_t in_port)
{
    ppe_packet_t ppep;
    ppe_packet_init(&ppep, data, len);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_WARN("Packet-in parsing failed");
        return;
    }

    if (ppe_header_get(&ppep, PPE_HEADER_8021Q)) {
        AIM_LOG_VERBOSE("Ignoring tagged packet");
        return;
    }

    /*
     * Get the start of LLDP header
     */
    uint8_t *header;
    if ((header = ppe_header_get(&ppep, PPE_HEADER_LLDP)) == NULL) {
        AIM_LOG_VERBOSE("Not an LLDP packet");
        return;
    }

    debug_counter_inc(&received_uplink_lldp);

    AIM_LOG_VERBOSE("Parsing LLDP packet");

    struct inband_controller new_controllers[MAX_INBAND_CONTROLLERS];
    int num_new_controllers = 0;

    struct lldp_tlv tlv;
    int remain = ppep.size - (header - ppep.data);
    const uint8_t *pos = header;
    while (inband_lldp_parse_tlv(&pos, &remain, &tlv)) {
        AIM_LOG_TRACE("Found tlv type=%u oui=%u subtype=%u payload_length=%u", tlv.type, tlv.oui, tlv.subtype, tlv.payload_length);
        if (tlv.type == LLDP_TLV_VENDOR && tlv.oui == LLDP_BSN_OUI &&
                tlv.subtype == LLDP_BSN_INBAND_CONTROLLER_ADDR) {
            AIM_LOG_TRACE("Found inband OpenFlow controller address TLV");

            if (num_controllers >= MAX_INBAND_CONTROLLERS) {
                AIM_LOG_WARN("Too many inband OpenFlow controller address TLVs in LLDP");
                debug_counter_inc(&invalid_management_tlv);
                continue;
            }

            if (tlv.payload_length != sizeof(of_ipv6_t)) {
                AIM_LOG_WARN("Unexpected length in OpenFlow controller address TLV");
                debug_counter_inc(&invalid_management_tlv);
                continue;
            }

            struct inband_controller *new_controller = &new_controllers[num_new_controllers];
            memset(new_controller, 0, sizeof(*new_controller));

            char addr_str[64];
            inet_ntop(AF_INET6, tlv.payload, addr_str, sizeof(addr_str));

            AIM_LOG_VERBOSE("Controller address: %s", addr_str);

            indigo_cxn_params_tcp_over_ipv6_t *proto = &new_controller->protocol_params.tcp_over_ipv6;
            if (inband_tls_enabled) {
                proto->protocol = INDIGO_CXN_PROTO_TLS_OVER_IPV6;
            } else {
                proto->protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV6;
            }
            snprintf(proto->controller_ip, sizeof(proto->controller_ip),
                    "%s%%%s", addr_str, inband_interface_name);
            proto->controller_port = 6653;

            /* Don't add duplicate controllers */
            int i;
            bool found = false;
            for (i = 0; i < num_new_controllers; i++) {
                struct inband_controller *other = &new_controllers[i];
                if (!memcmp(&other->protocol_params, &new_controller->protocol_params, sizeof(other->protocol_params))) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                num_new_controllers++;
            }
        }
    }

    synchronize_controllers(new_controllers, num_new_controllers);

    inband_send_lldp(in_port);

    retarget_logger();
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
            add_neighbor_entry(new);

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

/*
 * Create a permanent neighbor table entry for the controller
 *
 * Assumes that the controller's IPv6 address is constructed according to RFC
 * 2464, so that it can be directly translated to a MAC.
 *
 * This saves us from having to perform neighbor discovery, which is often
 * flaky.
 */
static void
add_neighbor_entry(struct inband_controller *ctrl)
{
    int rv;

    of_ipv6_t ipv6;
    char ipv6_str[64];
    strncpy(ipv6_str, ctrl->protocol_params.tcp_over_ipv6.controller_ip, sizeof(ipv6_str));
    *strchr(ipv6_str, '%') = '\0';
    if (inet_pton(AF_INET6, ipv6_str, &ipv6) < 1) {
        AIM_LOG_ERROR("Failed to parse IPv6 address '%s'", ipv6_str);
        return;
    }

    if (ipv6.addr[0] != 0xfe || ipv6.addr[1] != 0x80) {
        AIM_LOG_WARN("Controller address %s is not link-local", ipv6_str);
        return;
    }

    /* RFC 2464 section "Stateless Autoconfiguration" */
    of_mac_addr_t mac;
    mac.addr[0] = ipv6.addr[8] ^ 2;
    mac.addr[1] = ipv6.addr[9];
    mac.addr[2] = ipv6.addr[10];
    mac.addr[3] = ipv6.addr[13];
    mac.addr[4] = ipv6.addr[14];
    mac.addr[5] = ipv6.addr[15];

    struct nl_addr *ipv6_nladdr = nl_addr_build(AF_INET6, &ipv6, OF_IPV6_BYTES);
    AIM_TRUE_OR_DIE(ipv6_nladdr != NULL);

    struct nl_addr *mac_nladdr = nl_addr_build(AF_LLC, &mac, OF_MAC_ADDR_BYTES);
    AIM_TRUE_OR_DIE(mac_nladdr != NULL);

    struct rtnl_neigh *neigh = rtnl_neigh_alloc();
    AIM_TRUE_OR_DIE(neigh != NULL);
    rtnl_neigh_set_ifindex(neigh, if_nametoindex(inband_interface_name));
    rtnl_neigh_set_dst(neigh, ipv6_nladdr);
    rtnl_neigh_set_lladdr(neigh, mac_nladdr);
    rtnl_neigh_set_state(neigh, rtnl_neigh_str2state("permanent"));

    struct nl_sock *sk = nl_socket_alloc();
    if (sk == NULL) {
        AIM_LOG_ERROR("Failed to allocate netlink socket");
        goto out;
    }

    if ((rv = nl_connect(sk, NETLINK_ROUTE)) < 0) {
        AIM_LOG_ERROR("Failed to connect netlink socket: %s", nl_geterror(rv));
        goto out;
    }

    if ((rv = rtnl_neigh_add(sk, neigh, NLM_F_CREATE)) < 0) {
        AIM_LOG_ERROR("Failed to add neighbor entry %s -> %{mac}: %s", ipv6_str, &mac, nl_geterror(rv));
    } else {
        AIM_LOG_VERBOSE("Added neighbor entry %s -> %{mac}", ipv6_str, &mac);
    }

out:
    nl_socket_free(sk);
    rtnl_neigh_put(neigh);
    nl_addr_put(ipv6_nladdr);
    nl_addr_put(mac_nladdr);
}

void
inband_send_lldp(of_port_no_t port_no)
{
    struct lldp_builder builder;
    inband_lldp_builder_init(&builder);

    {
        uint8_t chassis_id[] = { 0x04, 0, 0, 0, 0, 0, 0 };
        of_dpid_t dpid = 0;
        indigo_core_dpid_get(&dpid);

        /* Use the lower 6 bytes of the DPID for the MAC address */
        int i;
        for (i = 0; i < 6; i++) {
            chassis_id[6-i] = dpid & 0xff;
            dpid >>= 8;
        }

        inband_lldp_append(&builder, 1, &chassis_id, sizeof(chassis_id));
    }

    {
        uint8_t port_id[INDIGO_PORT_NAME_MAX+1] = { 0x05 };
        char *port_name = (char *)port_id+1;
        get_port_name(port_no, port_name);
        inband_lldp_append(&builder, 2, &port_id, 1 + strnlen(port_name, INDIGO_PORT_NAME_MAX));
    }

    {
        uint16_t ttl = htons(120);
        inband_lldp_append(&builder, 3, &ttl, sizeof(ttl));
    }

    if (getenv("IVS_HOSTNAME") != NULL) {
        const char *hostname = getenv("IVS_HOSTNAME");
        inband_lldp_append(&builder, 5, hostname, strlen(hostname));
    } else {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        inband_lldp_append(&builder, 5, hostname, strnlen(hostname, sizeof(hostname)));
    }

    {
        const char *system_desc = "5c:16:c7:00:00:03";
        inband_lldp_append(&builder, 6, system_desc, strlen(system_desc));
    }

    of_octets_t octets = inband_lldp_finish(&builder);
    indigo_error_t rv = slshared_fwd_packet_out(&octets, OF_PORT_DEST_CONTROLLER,
                                                port_no,
                                                SLSHARED_CONFIG_PDU_QUEUE_PRIORITY);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to inject LLDP reply: %s", indigo_strerror(rv));
    } else {
        debug_counter_inc(&sent_lldp_reply);
    }
}

static void
retarget_logger(void)
{
    inband_logger_reset();

    struct sockaddr_storage saddr = { 0 };
    struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)&saddr;
    saddr6->sin6_family = AF_INET6;
    saddr6->sin6_port = htons(514);
    saddr6->sin6_scope_id = if_nametoindex(inband_interface_name);

    int i;
    for (i = 0; i < num_controllers; i++) {
        struct inband_controller *controller = &controllers[i];
        indigo_cxn_params_tcp_over_ipv6_t *proto = &controller->protocol_params.tcp_over_ipv6;
        if (proto->protocol == INDIGO_CXN_PROTO_TCP_OVER_IPV6) {
            char ip[64];
            strncpy(ip, proto->controller_ip, sizeof(ip));
            *strchr(ip, '%') = '\0';
            if (inet_pton(AF_INET6, ip, &saddr6->sin6_addr) < 1) {
                AIM_LOG_ERROR("Failed to parse IPv6 address '%s'", ip);
                continue;
            }
            inband_logger_add_target(&saddr);
        }
    }
}

/*
 * Get a port name by number
 *
 * This could be made much more efficient if PortManager had an interface
 * to get the info for a single port.
 */
static void
get_port_name(of_port_no_t port, indigo_port_name_t port_name)
{
    strcpy(port_name, "unknown");

    indigo_port_info_t *list;
    indigo_error_t rv = indigo_port_interface_list(&list);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to retrieve port list: %s", indigo_strerror(rv));
        return;
    }

    indigo_port_info_t *cur = list;
    while (cur != NULL) {
        if (cur->of_port == port) {
            strncpy(port_name, cur->port_name, INDIGO_PORT_NAME_MAX);
            break;
        }
        cur = cur->next;
    }

    indigo_port_interface_list_destroy(list);
}

void
inband_init(void)
{
    debug_counter_register(&received_uplink_lldp, "inband.received_uplink_lldp",
                           "Received an LLDP on an uplink port");
    debug_counter_register(&sent_lldp_reply, "inband.sent_lldp_reply",
                           "Sent a reply LLDP on an uplink port");
    debug_counter_register(&invalid_management_tlv, "inband.invalid_management_tlv",
                           "Found an invalid LLDP Management Address TLV");
    debug_counter_register(&controller_add_failed, "inband.controller_add_failed",
                           "Failed to add a controller specified in a LLDP");

    inband_lldp_init();

    inband_logger_init();
}

void
inband_enable_tls(void)
{
    inband_tls_enabled = true;
}

void
__inband_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
