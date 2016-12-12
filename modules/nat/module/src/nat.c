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
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <indigo/port_manager.h>
#include <SocketManager/socketmanager.h>
#include <debug_counter/debug_counter.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/errno.h>
#include <signal.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <endian.h>
#include <net/if.h>
#include <ivs/ivs.h>
#include "nat_int.h"
#include "nat_log.h"

struct nat_entry_key {
    char name[128];
};

struct nat_entry_value {
    of_ipv4_t external_ip;
    of_mac_addr_t external_mac;
    of_ipv4_t external_netmask;
    of_ipv4_t external_gateway_ip;
    of_mac_addr_t internal_mac;
    of_mac_addr_t internal_gateway_mac;
};

struct nat_entry {
    list_links_t links;
    struct nat_entry_key key;
    struct nat_entry_value value;
    int netns;
};

static void nat_container_teardown(struct nat_entry *entry);
static int create_netns(void);
static void enter_netns(int fd);
static int open_current_netns(void);
static bool run(const char *fmt, ...);
static indigo_error_t move_link(const char *name, int netns);
static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);
static struct nat_entry *find_nat_entry(const char *name, int name_len);

static indigo_core_gentable_t *nat_table;

static const indigo_core_gentable_ops_t nat_ops;

static int root_netns = -1;

static list_head_t nat_entries; /* struct nat_entry through links */

/* Debug counters */
static debug_counter_t add_success_counter;
static debug_counter_t add_failure_counter;
static debug_counter_t modify_success_counter;
static debug_counter_t modify_failure_counter;
static debug_counter_t delete_success_counter;

void
nat_init(void)
{
    AIM_LOG_VERBOSE("Initializing NAT module");

    indigo_core_gentable_register("nat", &nat_ops, NULL, 4096, 128,
                                  &nat_table);

    root_netns = open_current_netns();

    debug_counter_register(
        &add_success_counter, "nat.table_add",
        "NAT table entry added by the controller");

    debug_counter_register(
        &add_failure_counter, "nat.table_add_failure",
        "NAT table entry unsuccessfully added by the controller");

    debug_counter_register(
        &modify_success_counter, "nat.table_modify",
        "NAT table entry modified by the controller");

    debug_counter_register(
        &modify_failure_counter, "nat.table_modify_failure",
        "NAT table entry unsuccessfully modified by the controller");

    debug_counter_register(
        &delete_success_counter, "nat.table_delete",
        "NAT table entry deleted by the controller");

    indigo_core_message_listener_register(message_listener);

    list_init(&nat_entries);
}

void
__nat_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}

static void
format_port_name(char ifname[IFNAMSIZ+1], of_mac_addr_t mac)
{
    snprintf(ifname, IFNAMSIZ+1, "nat%02x%02x%02x%02x%02x%02x",
             mac.addr[0], mac.addr[1], mac.addr[2],
             mac.addr[3], mac.addr[4], mac.addr[5]);
}


/* nat container setup/teardown */
static indigo_error_t
nat_container_setup(struct nat_entry *entry)
{
    AIM_LOG_VERBOSE("Creating NAT container %s", entry->key.name);

    /*
     * Create and enter a new network namespace with unshare(CLONE_NEWNET)
     * Save a reference to the new namespace with open("/proc/self/ns/net", O_RDONLY)
     */
    int new_netns;
    if ((new_netns = create_netns()) < 0) {
        return INDIGO_ERROR_UNKNOWN;
    }
    entry->netns = new_netns;

    char ext_ifname[IFNAMSIZ+1];
    format_port_name(ext_ifname, entry->value.external_mac);
    char int_ifname[IFNAMSIZ+1];
    format_port_name(int_ifname, entry->value.internal_mac);

    /* Fake IP for next-hop to fabric router */
    const char *internal_ip = "127.100.0.1";
    const char *internal_netmask = "255.255.255.0";
    const char *internal_gateway_ip = "127.100.0.2";

    bool ok = true;

    /* Disable IPv6 to stop the container from sending autoconfiguration packets */
    ok = ok && run("echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6");

    /* Enable IPv4 forwarding */
    ok = ok && run("echo 1 > /proc/sys/net/ipv4/ip_forward");

    /* Enable conntrack counters */
    ok = ok && run("echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct");

    /* Create two veth pairs */
    ok = ok && run("ip link add ext type veth peer name %s", ext_ifname);
    ok = ok && run("ip link add int type veth peer name %s", int_ifname);

    /* Disable the loopback interface to allow us to use the 127.0.0.0/8 subnet */
    ok = ok && run("ip link set dev lo down");

    /* Configure MACs, IPs, and netmasks on the container side of each veth pair */
    ok = ok && run("ip link set dev ext up mtu %d address %{mac}", IVS_MTU_SIZE_WITH_VLAN, &entry->value.external_mac);
    ok = ok && run("ip addr add %{ipv4a}/%{ipv4a} dev ext", entry->value.external_ip, entry->value.external_netmask);
    ok = ok && run("ip link set dev int up mtu %d address %{mac}", IVS_MTU_SIZE_WITH_VLAN, &entry->value.internal_mac);
    ok = ok && run("ip addr add %s/%s dev int", internal_ip, internal_netmask);

    /* Create the default route to external_gateway */
    ok = ok && run("ip route add to default via %{ipv4a}", entry->value.external_gateway_ip);

    /* Create the policy-based routing rule and route to internal_gateway */
    ok = ok && run("ip route add to default via %s table 1000", internal_gateway_ip);
    ok = ok && run("ip rule add priority 1 iif ext lookup 1000");

    /* Create static ARP entry for the internal gateway */
    ok = ok && run("ip neigh replace %s lladdr %{mac} nud permanent dev int", internal_gateway_ip, &entry->value.internal_gateway_mac);

    /* Setup iptables for NAT */
    ok = ok && run("iptables -t nat -A POSTROUTING -o ext -j SNAT --to-source %{ipv4a}", entry->value.external_ip);
    ok = ok && run("iptables -A FORWARD -i ext -m state --state RELATED,ESTABLISHED -j ACCEPT");
    ok = ok && run("iptables -A FORWARD -o ext -j ACCEPT");
    ok = ok && run("iptables -P FORWARD DROP");

    /* Setup MTU on switch side of veth pair */
    ok = ok && run("ip link set dev %s mtu %d", ext_ifname, IVS_MTU_SIZE_WITH_VLAN);
    ok = ok && run("ip link set dev %s mtu %d", int_ifname, IVS_MTU_SIZE_WITH_VLAN);

    /* Move the switch side of each veth pair into the original namespace */
    ok = ok && move_link(int_ifname, root_netns) == INDIGO_ERROR_NONE;
    ok = ok && move_link(ext_ifname, root_netns) == INDIGO_ERROR_NONE;

    /* Revert to the original namespace */
    enter_netns(root_netns);

    /* Connect the switch side of each veth pair to IVS */
    ok = ok && indigo_port_interface_add(int_ifname, OF_PORT_DEST_NONE, NULL) == INDIGO_ERROR_NONE;
    ok = ok && indigo_port_interface_add(ext_ifname, OF_PORT_DEST_NONE, NULL) == INDIGO_ERROR_NONE;

    if (ok) {
        return INDIGO_ERROR_NONE;
    } else {
        nat_container_teardown(entry);
        return INDIGO_ERROR_UNKNOWN;
    }
}

static void
wait_for_interface_delete(const char *name)
{
    /* Wait for up to one second before giving up */
    int i = 0;
    while (if_nametoindex(name) != 0 && i < 10) {
        usleep(1000 * (1 << i++));
    }

    if (if_nametoindex(name) != 0) {
        AIM_LOG_WARN("interface %s was not deleted within one second", name);
    }
}

static void
nat_container_teardown(struct nat_entry *entry)
{
    AIM_LOG_VERBOSE("Destroying NAT container %s", entry->key.name);

    char ext_ifname[IFNAMSIZ+1];
    format_port_name(ext_ifname, entry->value.external_mac);
    char int_ifname[IFNAMSIZ+1];
    format_port_name(int_ifname, entry->value.internal_mac);

    indigo_port_interface_remove(ext_ifname);
    indigo_port_interface_remove(int_ifname);

    /* Receive the vport deleted notifications
     *
     * This allows future container setups with the same MACs to succeed
     * without needing to go to the event loop first.
     */
    ind_ovs_handle_multicast();

    /* Closing the netns will delete the veth pairs */
    close(entry->netns);

    /*
     * The kernel can take over 100ms after close() to delete the interfaces.
     * We need to wait until the interfaces are gone so that they can
     * (potentially) be added again immediately.
     */
    wait_for_interface_delete(ext_ifname);
    wait_for_interface_delete(int_ifname);
}

/* nat table operations */

static indigo_error_t
nat_parse_key(of_list_bsn_tlv_t *tlvs, struct nat_entry_key *key)
{
    of_object_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_NAME) {
        of_octets_t name;
        of_bsn_tlv_name_value_get(&tlv, &name);
        if (name.bytes >= sizeof(key->name)) {
            AIM_LOG_ERROR("name key TLV too long");
            return INDIGO_ERROR_PARAM;
        }
        memcpy(key->name, name.data, name.bytes);
    } else {
        AIM_LOG_ERROR("expected name key TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_parse_value(of_list_bsn_tlv_t *tlvs, struct nat_entry_value *value)
{
    of_object_t tlv;

    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External IP */
    if (tlv.object_id == OF_BSN_TLV_EXTERNAL_IP) {
        of_bsn_tlv_external_ip_value_get(&tlv, &value->external_ip);
    } else {
        AIM_LOG_ERROR("expected external_ip value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External MAC */
    if (tlv.object_id == OF_BSN_TLV_EXTERNAL_MAC) {
        of_bsn_tlv_external_mac_value_get(&tlv, &value->external_mac);
    } else {
        AIM_LOG_ERROR("expected external_mac value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External netmask */
    if (tlv.object_id == OF_BSN_TLV_EXTERNAL_NETMASK) {
        of_bsn_tlv_external_netmask_value_get(&tlv, &value->external_netmask);
    } else {
        AIM_LOG_ERROR("expected ipv4 external_netmask value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External gateway IP */
    if (tlv.object_id == OF_BSN_TLV_EXTERNAL_GATEWAY_IP) {
        of_bsn_tlv_external_gateway_ip_value_get(&tlv, &value->external_gateway_ip);
    } else {
        AIM_LOG_ERROR("expected external_gateway_ip value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal MAC */
    if (tlv.object_id == OF_BSN_TLV_INTERNAL_MAC) {
        of_bsn_tlv_internal_mac_value_get(&tlv, &value->internal_mac);
    } else {
        AIM_LOG_ERROR("expected internal_mac value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal gateway MAC */
    if (tlv.object_id == OF_BSN_TLV_INTERNAL_GATEWAY_MAC) {
        of_bsn_tlv_internal_gateway_mac_value_get(&tlv, &value->internal_gateway_mac);
    } else {
        AIM_LOG_ERROR("expected internal_gateway_mac value TLV, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct nat_entry_key key;
    struct nat_entry_value value;
    struct nat_entry *entry;

    rv = nat_parse_key(key_tlvs, &key);
    if (rv < 0) {
        debug_counter_inc(&add_failure_counter);
        return rv;
    }

    rv = nat_parse_value(value_tlvs, &value);
    if (rv < 0) {
        debug_counter_inc(&add_failure_counter);
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    if ((rv = nat_container_setup(entry)) < 0) {
        aim_free(entry);
        debug_counter_inc(&add_failure_counter);
        return rv;
    }

    list_push(&nat_entries, &entry->links);

    *entry_priv = entry;
    debug_counter_inc(&add_success_counter);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct nat_entry_value value;
    struct nat_entry *entry = entry_priv;

    rv = nat_parse_value(value_tlvs, &value);
    if (rv < 0) {
        debug_counter_inc(&modify_failure_counter);
        return rv;
    }

    nat_container_teardown(entry);

    struct nat_entry_value old_value = entry->value;
    entry->value = value;

    if ((rv = nat_container_setup(entry)) < 0) {
        entry->value = old_value;
        if (nat_container_setup(entry) < 0) {
            AIM_LOG_ERROR("Failed to restore previous NAT entry after failed modify");
            /* NAT will be permanently broken for this entry */
        }
        debug_counter_inc(&modify_failure_counter);
        return rv;
    }

    debug_counter_inc(&modify_success_counter);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct nat_entry *entry = entry_priv;
    list_remove(&entry->links);
    nat_container_teardown(entry);
    aim_free(entry);
    debug_counter_inc(&delete_success_counter);
    return INDIGO_ERROR_NONE;
}

static void
nat_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* No stats */
}

static const indigo_core_gentable_ops_t nat_ops = {
    .add = nat_add,
    .modify = nat_modify,
    .del = nat_delete,
    .get_stats = nat_get_stats,
};


/*
 * Create and enter a new network namespace
 *
 * Returns a file descriptor referring to the new network namespace, or -1.
 */
int
create_netns(void)
{
    if (syscall(__NR_unshare, CLONE_NEWNET) < 0) {
        AIM_LOG_ERROR("Failed to create network namespace: %s", strerror(errno));
        return -1;
    }
    return open_current_netns();
}

/*
 * Enter an existing network namespace
 */
void
enter_netns(int fd)
{
    if (syscall(__NR_setns, fd, CLONE_NEWNET) < 0) {
        perror("syscall");
        abort();
    }
}

/*
 * Get a file descriptor for the current network namespace
 */
int
open_current_netns(void)
{
    int fd = open("/proc/self/ns/net", O_RDONLY);
    if (fd < 0) {
        perror("open");
        abort();
    }
    return fd;
}

/*
 * Run a shell command with AIM printf formatting
 *
 * Returns true if the command succeeded, false otherwise.
 */
static bool
run(const char *fmt, ...)
{
    bool result;

    va_list args;
    va_start(args, fmt);
    char *cmd = aim_vdfstrdup(fmt, args);
    va_end(args);

    AIM_LOG_VERBOSE("Running command '%s'", cmd);

    int status = system(cmd);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) != 0) {
            AIM_LOG_ERROR("Failed to execute command '%s': exited with status %u", cmd, WEXITSTATUS(status));
            result = false;
        } else {
            result = true;
        }
    } else if (WIFSIGNALED(status)) {
        AIM_LOG_ERROR("Failed to execute command '%s': terminated by signal %u", cmd, WTERMSIG(status));
        result = false;
    } else {
        AIM_LOG_ERROR("Failed to execute command '%s': %s", cmd, strerror(errno));
        result = false;
    }

    aim_free(cmd);

    return result;
}

/* Move a link from the current netns to another one */
static indigo_error_t
move_link(const char *name, int netns)
{
    int rv;

    struct nl_sock *sk = nl_socket_alloc();
    if (sk == NULL) {
        AIM_DIE("failed to allocate netlink socket");
    }

    if ((rv = nl_connect(sk, NETLINK_ROUTE)) < 0) {
        AIM_DIE("Failed to connect netlink socket: %s", nl_geterror(rv));
    }

    struct nl_msg *msg = nlmsg_alloc();
    AIM_TRUE_OR_DIE(msg != NULL);
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    nlh->nlmsg_type = RTM_SETLINK;
    struct ifinfomsg *ifm = nlmsg_reserve(msg, sizeof(*ifm), NLMSG_ALIGNTO);
    nla_put_string(msg, IFLA_IFNAME, name);
    nla_put_u32(msg, IFLA_NET_NS_FD, netns);

    if ((rv = nl_send_sync(sk, msg)) < 0) {
        AIM_LOG_ERROR("Moving interface to netns failed: %s", nl_geterror(rv));
        nl_socket_free(sk);
        return INDIGO_ERROR_UNKNOWN;
    }

    nl_socket_free(sk);
    return INDIGO_ERROR_NONE;
}

struct nat_stats_state {
    of_bsn_generic_stats_reply_t *reply;
    indigo_cxn_id_t cxn_id;
    uint32_t xid;
    struct nl_sock *sk;
};

static void
nat_tuple_to_tlvs(struct nlattr *attr, of_list_bsn_tlv_t *tlvs)
{
    of_bsn_tlv_t bucket;
    of_bsn_tlv_t tlv;
    uint8_t version = tlvs->version;

    of_bsn_tlv_bucket_init(&bucket, version, -1, 1);
    if (of_list_bsn_tlv_append_bind(tlvs, &bucket)) {
        AIM_DIE("Unexpected failure to append NAT stats entry");
    }

    of_list_bsn_tlv_t bucket_tlvs;
    of_bsn_tlv_bucket_value_bind(&bucket, &bucket_tlvs);
    tlvs = &bucket_tlvs;

    struct nlattr *cta_tuple_attrs[CTA_TUPLE_MAX+1];
    if (nla_parse_nested(cta_tuple_attrs, CTA_TUPLE_MAX, attr, NULL) < 0) {
        abort();
    }

    if (cta_tuple_attrs[CTA_TUPLE_IP]) {
        struct nlattr *cta_ip_attrs[CTA_IP_MAX+1];
        if (nla_parse_nested(cta_ip_attrs, CTA_IP_MAX, cta_tuple_attrs[CTA_TUPLE_IP], NULL) < 0) {
            abort();
        }

        if (cta_ip_attrs[CTA_IP_V4_SRC]) {
            uint32_t ip = nla_get_u32(cta_ip_attrs[CTA_IP_V4_SRC]);
            of_bsn_tlv_ipv4_src_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_ipv4_src_value_set(&tlv, ntohl(ip));
        }

        if (cta_ip_attrs[CTA_IP_V4_DST]) {
            uint32_t ip = nla_get_u32(cta_ip_attrs[CTA_IP_V4_DST]);
            of_bsn_tlv_ipv4_dst_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_ipv4_dst_value_set(&tlv, ntohl(ip));
        }
    }

    if (cta_tuple_attrs[CTA_TUPLE_PROTO]) {
        struct nlattr *cta_proto_attrs[CTA_PROTO_MAX+1];
        if (nla_parse_nested(cta_proto_attrs, CTA_PROTO_MAX, cta_tuple_attrs[CTA_TUPLE_PROTO], NULL) < 0) {
            abort();
        }

        if (cta_proto_attrs[CTA_PROTO_NUM]) {
            uint8_t proto = nla_get_u8(cta_proto_attrs[CTA_PROTO_NUM]);
            of_bsn_tlv_ip_proto_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_ip_proto_value_set(&tlv, proto);
        }

        if (cta_proto_attrs[CTA_PROTO_SRC_PORT]) {
            uint16_t port = ntohs(nla_get_u16(cta_proto_attrs[CTA_PROTO_SRC_PORT]));
            of_bsn_tlv_tcp_src_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_tcp_src_value_set(&tlv, port);
        }

        if (cta_proto_attrs[CTA_PROTO_DST_PORT]) {
            uint16_t port = ntohs(nla_get_u16(cta_proto_attrs[CTA_PROTO_DST_PORT]));
            of_bsn_tlv_tcp_dst_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_tcp_dst_value_set(&tlv, port);
        }

        if (cta_proto_attrs[CTA_PROTO_ICMP_ID]) {
            uint16_t id = ntohs(nla_get_u16(cta_proto_attrs[CTA_PROTO_ICMP_ID]));
            of_bsn_tlv_icmp_id_init(&tlv, version, -1, 1);
            if (of_list_bsn_tlv_append_bind(tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_icmp_id_value_set(&tlv, id);
        }
    }
}

static void
nat_stats_iterator(struct nat_stats_state *state, struct nlmsghdr *nlh)
{
    of_bsn_generic_stats_reply_t *reply = state->reply;

    /* Ensure we have at least 4K for a stats entry (currently using at most 132 bytes) */
    if (reply->length > 60*1024) {
        of_version_t version = state->reply->version;
        of_bsn_generic_stats_reply_flags_set(state->reply, OF_STATS_REPLY_FLAG_REPLY_MORE);
        indigo_cxn_send_controller_message(state->cxn_id, state->reply);
        state->reply = of_bsn_generic_stats_reply_new(version);
        of_bsn_generic_stats_reply_xid_set(state->reply, state->xid);
    }

    of_list_bsn_tlv_t entries;
    of_bsn_generic_stats_reply_entries_bind(reply, &entries);

    of_bsn_generic_stats_entry_t entry;
    of_bsn_generic_stats_entry_init(&entry, reply->version, -1, 1);
    if (of_list_bsn_generic_stats_entry_append_bind(&entries, &entry)) {
        AIM_DIE("Unexpected failure to append NAT stats entry");
    }

    of_list_bsn_tlv_t tlvs;
    of_bsn_generic_stats_entry_tlvs_bind(&entry, &tlvs);
    of_bsn_tlv_t tlv;

    struct nlattr *cta_attrs[CTA_MAX+1];
    if (nlmsg_parse(nlh, sizeof(struct nfgenmsg), cta_attrs, CTA_MAX, NULL) < 0) {
        abort();
    }

    if (cta_attrs[CTA_TUPLE_ORIG]) {
        nat_tuple_to_tlvs(cta_attrs[CTA_TUPLE_ORIG], &tlvs);
    }

    if (cta_attrs[CTA_TUPLE_REPLY]) {
        nat_tuple_to_tlvs(cta_attrs[CTA_TUPLE_REPLY], &tlvs);
    }

    if (cta_attrs[CTA_COUNTERS_ORIG]) {
        struct nlattr *cta_counters_attrs[CTA_COUNTERS_MAX+1];
        if (nla_parse_nested(cta_counters_attrs, CTA_COUNTERS_MAX, cta_attrs[CTA_COUNTERS_ORIG], NULL) < 0) {
            abort();
        }

        if (cta_counters_attrs[CTA_COUNTERS_PACKETS]) {
            uint64_t value = be64toh(nla_get_u64(cta_counters_attrs[CTA_COUNTERS_PACKETS]));
            of_bsn_tlv_tx_packets_init(&tlv, reply->version, -1, 1);
            if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_tx_packets_value_set(&tlv, value);
        }

        if (cta_counters_attrs[CTA_COUNTERS_BYTES]) {
            uint64_t value = be64toh(nla_get_u64(cta_counters_attrs[CTA_COUNTERS_BYTES]));
            of_bsn_tlv_tx_bytes_init(&tlv, reply->version, -1, 1);
            if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_tx_bytes_value_set(&tlv, value);
        }
    }

    if (cta_attrs[CTA_COUNTERS_REPLY]) {
        struct nlattr *cta_counters_attrs[CTA_COUNTERS_MAX+1];
        if (nla_parse_nested(cta_counters_attrs, CTA_COUNTERS_MAX, cta_attrs[CTA_COUNTERS_REPLY], NULL) < 0) {
            abort();
        }

        if (cta_counters_attrs[CTA_COUNTERS_PACKETS]) {
            uint64_t value = be64toh(nla_get_u64(cta_counters_attrs[CTA_COUNTERS_PACKETS]));
            of_bsn_tlv_rx_packets_init(&tlv, reply->version, -1, 1);
            if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_rx_packets_value_set(&tlv, value);
        }

        if (cta_counters_attrs[CTA_COUNTERS_BYTES]) {
            uint64_t value = be64toh(nla_get_u64(cta_counters_attrs[CTA_COUNTERS_BYTES]));
            of_bsn_tlv_rx_bytes_init(&tlv, reply->version, -1, 1);
            if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
                AIM_DIE("Unexpected failure to append NAT stats entry");
            }
            of_bsn_tlv_rx_bytes_value_set(&tlv, value);
        }
    }

    if (cta_attrs[CTA_TIMEOUT]) {
        uint32_t timeout = ntohl(nla_get_u32(cta_attrs[CTA_TIMEOUT]));
        of_bsn_tlv_idle_timeout_init(&tlv, reply->version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            AIM_DIE("Unexpected failure to append NAT stats entry");
        }
        of_bsn_tlv_idle_timeout_value_set(&tlv, timeout * 1000);
    }
}

static ind_soc_task_status_t
nat_stats_task_callback(void *cookie)
{
    struct nat_stats_state *state = cookie;

    while (!ind_soc_should_yield()) {
        struct sockaddr_nl nla = {0};
        uint8_t *buf = NULL;
        int n = nl_recv(state->sk, &nla, &buf, NULL);
        if (n <= 0) {
            AIM_LOG_ERROR("Error %d reading NAT stats");
            free(buf);
            goto finished;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
        while (nlmsg_ok(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                free(buf);
                goto finished;
            }

            nat_stats_iterator(state, nlh);
            nlh = nlmsg_next(nlh, &n);
        }

        free(buf);
    }

    return IND_SOC_TASK_CONTINUE;

finished:
    indigo_cxn_send_controller_message(state->cxn_id, state->reply);
    indigo_cxn_resume(state->cxn_id);
    nl_socket_free(state->sk);
    aim_free(state);
    return IND_SOC_TASK_FINISHED;
}

static indigo_core_listener_result_t
handle_nat_stats_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint32_t xid;
    of_str64_t stats_name;
    of_bsn_generic_stats_request_xid_get(msg, &xid);
    of_bsn_generic_stats_request_name_get(msg, &stats_name);
    of_octets_t nat_name;

    if (strcmp(stats_name, "nat")) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    {
        of_list_bsn_tlv_t tlvs;
        of_object_t tlv;

        of_bsn_generic_stats_request_tlvs_bind(msg, &tlvs);

        if (of_list_bsn_tlv_first(&tlvs, &tlv) < 0) {
            AIM_LOG_ERROR("empty NAT stats request TLV list");
            /* TODO send error */
            return INDIGO_CORE_LISTENER_RESULT_DROP;
        }

        if (tlv.object_id == OF_BSN_TLV_NAME) {
            of_bsn_tlv_name_value_get(&tlv, &nat_name);
        } else {
            AIM_LOG_ERROR("expected name TLV, instead got %s", of_object_id_str[tlv.object_id]);
            /* TODO send error */
            return INDIGO_CORE_LISTENER_RESULT_DROP;
        }
    }

    of_object_t *reply = of_bsn_generic_stats_reply_new(msg->version);
    of_bsn_generic_stats_reply_xid_set(reply, xid);

    /*
     * tlvs: ipv4_src, ipv4_dst, ipv4_proto, tcp_src, tcp_dst, ipv4_src,
     *       tcp_src, tx_packets, tx_bytes, rx_packets, rx_bytes, idle_time
     */

    struct nat_entry *nat_entry = find_nat_entry((char *)nat_name.data, nat_name.bytes);
    if (nat_entry == NULL) {
        AIM_LOG_VERBOSE("Received NAT stats request for nonexistent container");
        indigo_cxn_send_controller_message(cxn_id, reply);
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    struct nat_stats_state *state = aim_zmalloc(sizeof(*state));
    state->reply = reply;
    state->cxn_id = cxn_id;
    state->xid = xid;

    enter_netns(nat_entry->netns);

    state->sk = nl_socket_alloc();
    if (state->sk == NULL) {
        AIM_DIE("failed to allocate netlink socket");
    }

    int rv;
    if ((rv = nl_connect(state->sk, NETLINK_NETFILTER) < 0)) {
        AIM_DIE("Failed to connect netlink socket: %s", nl_geterror(rv));
    }

    enter_netns(root_netns);

    struct nl_msg *nlmsg = nlmsg_alloc();
    AIM_TRUE_OR_DIE(nlmsg != NULL);
    struct nlmsghdr *hdr = nlmsg_put(
        nlmsg, NL_AUTO_PORT, NL_AUTO_SEQ,
        (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
        sizeof(struct nfgenmsg), NLM_F_DUMP);

    struct nfgenmsg *nfmsg = nlmsg_data(hdr);
    nfmsg->nfgen_family = 0;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    if (nl_send_auto(state->sk, nlmsg) < 0) {
        AIM_DIE("Failed to send NAT stats request to kernel");
    }

    indigo_cxn_pause(state->cxn_id);

    rv = ind_soc_task_register(nat_stats_task_callback, state, IND_SOC_NORMAL_PRIORITY);
    if (rv != INDIGO_ERROR_NONE) {
        indigo_cxn_resume(state->cxn_id);
        nl_socket_free(state->sk);
        aim_free(state);
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static struct nat_entry *
find_nat_entry(const char *name, int name_len)
{
    list_links_t *cur;
    LIST_FOREACH(&nat_entries, cur) {
        struct nat_entry *nat_entry = container_of(cur, links, struct nat_entry);

        if (!strncmp(nat_entry->key.name, name, name_len)) {
            return nat_entry;
        }
    }

    return NULL;
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_GENERIC_STATS_REQUEST:
        return handle_nat_stats_request(cxn_id, msg);
    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}
