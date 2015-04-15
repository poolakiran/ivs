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

#include <pipeline/pipeline.h>
#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <packet_trace/packet_trace.h>
#include <arpa/inet.h>
#include "table_ifp.h"
#include "table_vfp.h"

#define AIM_LOG_MODULE_NAME pipeline_bigtap
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

/* Overall minimum average interval between packet-ins (in us) */
#define PKTIN_INTERVAL 3000

/* Overall packet-in burstiness tolerance. */
#define PKTIN_BURST_SIZE 32

static struct ifp_key make_ifp_key(const struct ind_ovs_parsed_key *key);
static struct vfp_key make_vfp_key(const struct ind_ovs_parsed_key *key);
static void pktin(struct action_context *actx, uint8_t reason);

struct ind_ovs_pktin_socket pktin_soc;
static const of_mac_addr_t slow_protocols_mac = { { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 } };
static const of_mac_addr_t cdp_mac = { { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc } };

static void
pipeline_bigtap_init(const char *name)
{
    ind_ovs_pktin_socket_register(&pktin_soc, NULL, PKTIN_INTERVAL,
                                  PKTIN_BURST_SIZE);
    pipeline_bigtap_table_ifp_register();
    pipeline_bigtap_table_vfp_register();
}

static void
pipeline_bigtap_finish(void)
{
    pipeline_bigtap_table_ifp_unregister();
    pipeline_bigtap_table_vfp_unregister();
    ind_ovs_pktin_socket_unregister(&pktin_soc);
}

indigo_error_t
pipeline_bigtap_process(struct ind_ovs_parsed_key *key,
                        struct ind_ovs_parsed_key *mask,
                        struct xbuf *stats,
                        struct action_context *actx)
{
    uint64_t populated = mask->populated;
    memset(mask, 0xff, sizeof(*mask));
    mask->populated = populated;

    /* LLDP */
    if (key->ethertype == htons(0x88cc)) {
        packet_trace("sending LLDP packet to the controller");
        pktin(actx, OF_PACKET_IN_REASON_NO_MATCH);
        return INDIGO_ERROR_NONE;
    }

    /* LACP */
    if (!memcmp(key->ethernet.eth_dst, slow_protocols_mac.addr, OF_MAC_ADDR_BYTES)) {
        packet_trace("sending slow protocols packet to the controller");
        pktin(actx, OF_PACKET_IN_REASON_NO_MATCH);
        return INDIGO_ERROR_NONE;
    }

    /* CDP */
    if (!memcmp(key->ethernet.eth_dst, cdp_mac.addr, OF_MAC_ADDR_BYTES)) {
        packet_trace("sending CDP packet to the controller");
        pktin(actx, OF_PACKET_IN_REASON_NO_MATCH);
        return INDIGO_ERROR_NONE;
    }

    struct vfp_key vfp_key = make_vfp_key(key);
    struct vfp_entry *vfp_entry =
        pipeline_bigtap_table_vfp_lookup(&vfp_key);
    if (vfp_entry && vfp_entry->value.cpu) {
        pktin(actx, OF_PACKET_IN_REASON_NO_MATCH);
    }

    struct ifp_key ifp_key = make_ifp_key(key);
    struct ifp_entry *ifp_entry =
        pipeline_bigtap_table_ifp_lookup(&ifp_key);
    if (ifp_entry) {
        if (ifp_entry->value.new_vlan_vid != VLAN_INVALID) {
            action_set_vlan_vid(actx, ifp_entry->value.new_vlan_vid);
        }

        uint32_t out_port;
        AIM_BITMAP_ITER(&ifp_entry->value.out_port_bitmap, out_port) {
            action_output(actx, out_port);
        }
    }

    return INDIGO_ERROR_NONE;
}

static struct ifp_key
make_ifp_key(const struct ind_ovs_parsed_key *key)
{
    struct ifp_key ifp_key;
    memset(&ifp_key, 0, sizeof(ifp_key));

    if (key->in_port == OVSP_LOCAL) {
        ifp_key.in_port = OF_PORT_DEST_LOCAL;
    } else {
        ifp_key.in_port = key->in_port;
    }

    /* Set a bit in the in_ports bitmap */
    if (key->in_port < 128) {
        uint32_t idx = key->in_port;
        uint32_t word = 3 - idx/32;
        uint32_t bit = idx % 32;
        ifp_key.in_ports[word] = 1 << bit;
    }

    memcpy(ifp_key.eth_dst, key->ethernet.eth_dst, OF_MAC_ADDR_BYTES);
    memcpy(ifp_key.eth_src, key->ethernet.eth_src, OF_MAC_ADDR_BYTES);

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        ifp_key.eth_type = ntohs(key->ethertype);
        if (ifp_key.eth_type <= OF_DL_TYPE_NOT_ETH_TYPE) {
            ifp_key.eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
        }
    } else {
        ifp_key.eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_VLAN)) {
        ifp_key.vlan = ntohs(key->vlan) | VLAN_CFI_BIT;
    } else {
        ifp_key.vlan = 0;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV4)) {
        ifp_key.ip_tos = key->ipv4.ipv4_tos;
        ifp_key.ip_proto = key->ipv4.ipv4_proto;
        ifp_key.ipv4_src = ntohl(key->ipv4.ipv4_src);
        ifp_key.ipv4_dst = ntohl(key->ipv4.ipv4_dst);
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV6)) {
        ifp_key.ip_tos = key->ipv6.ipv6_tclass;
        ifp_key.ip_proto = key->ipv6.ipv6_proto;
        memcpy(&ifp_key.ipv6_src, &key->ipv6.ipv6_src, OF_IPV6_BYTES);
        memcpy(&ifp_key.ipv6_dst, &key->ipv6.ipv6_dst, OF_IPV6_BYTES);
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_TCP)) {
        ifp_key.tp_src = ntohs(key->tcp.tcp_src);
        ifp_key.tp_dst = ntohs(key->tcp.tcp_dst);
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_UDP)) {
        ifp_key.tp_src = ntohs(key->udp.udp_src);
        ifp_key.tp_dst = ntohs(key->udp.udp_dst);
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ICMP)) {
        ifp_key.tp_src = key->icmp.icmp_type & 0xff;
        ifp_key.tp_dst = key->icmp.icmp_code & 0xff;
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ICMPV6)) {
        ifp_key.tp_src = key->icmpv6.icmpv6_type & 0xff;
        ifp_key.tp_dst = key->icmpv6.icmpv6_code & 0xff;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_TCP_FLAGS)) {
        ifp_key.tcp_flags = ntohs(key->tcp_flags);
    }

    return ifp_key;
}

static struct vfp_key
make_vfp_key(const struct ind_ovs_parsed_key *key)
{
    struct vfp_key vfp_key;
    memset(&vfp_key, 0, sizeof(vfp_key));

    if (key->in_port == OVSP_LOCAL) {
        vfp_key.in_port = OF_PORT_DEST_LOCAL;
    } else {
        vfp_key.in_port = key->in_port;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_ETHERTYPE)) {
        vfp_key.eth_type = ntohs(key->ethertype);
        if (vfp_key.eth_type <= OF_DL_TYPE_NOT_ETH_TYPE) {
            vfp_key.eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
        }
    } else {
        vfp_key.eth_type = OF_DL_TYPE_NOT_ETH_TYPE;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV4)) {
        vfp_key.ip_proto = key->ipv4.ipv4_proto;
    } else if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_IPV6)) {
        vfp_key.ip_proto = key->ipv6.ipv6_proto;
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_UDP)) {
        vfp_key.tp_src = ntohs(key->udp.udp_src);
        vfp_key.tp_dst = ntohs(key->udp.udp_dst);
    }

    if (ATTR_BITMAP_TEST(key->populated, OVS_KEY_ATTR_TCP_FLAGS)) {
        vfp_key.tcp_flags = ntohs(key->tcp_flags);
    }

    return vfp_key;
}

static void
pktin(struct action_context *actx, uint8_t reason)
{
    uint64_t userdata = IVS_PKTIN_USERDATA(reason, 0);
    uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&pktin_soc);
    action_userspace(actx, &userdata, sizeof(uint64_t), netlink_port);
}

static struct pipeline_ops pipeline_bigtap_ops = {
    .init = pipeline_bigtap_init,
    .finish = pipeline_bigtap_finish,
    .process = pipeline_bigtap_process,
};

void
__pipeline_bigtap_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("bigtap-full-match", &pipeline_bigtap_ops);
}
