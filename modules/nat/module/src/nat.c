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
#include "nat_int.h"
#include "nat_log.h"

struct nat_entry_key {
    uint32_t external_ip;
};

struct nat_entry_value {
    of_mac_addr_t external_mac;
    of_mac_addr_t external_gateway_mac;
    of_mac_addr_t internal_mac;
    of_mac_addr_t internal_gateway_mac;
};

struct nat_entry {
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

static indigo_core_gentable_t *nat_table;

static const indigo_core_gentable_ops_t nat_ops;

static int root_netns = -1;

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
}

void
__nat_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}


/* nat container setup/teardown */
static indigo_error_t
nat_container_setup(struct nat_entry *entry)
{
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
    snprintf(ext_ifname, sizeof(ext_ifname), "nat-%08x-e", entry->key.external_ip);
    char int_ifname[IFNAMSIZ+1];
    snprintf(int_ifname, sizeof(int_ifname), "nat-%08x-i", entry->key.external_ip);

    /* Fake IP for next-hop on the internal interface */
    const char *internal_ip = "127.100.0.1";
    const char *internal_netmask = "255.255.255.0";
    const char *internal_gateway_ip = "127.100.0.2";

    /* Fake IP for next-hop on the external interface */
    const char *external_ip = "127.100.1.1";
    const char *external_netmask = "255.255.255.0";
    const char *external_gateway_ip = "127.100.1.2";

    bool ok = true;

    /* Disable IPv6 to stop the container from sending autoconfiguration packets */
    ok = ok && run("echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6");

    /* Enable IPv4 forwarding */
    ok = ok && run("echo 1 > /proc/sys/net/ipv4/ip_forward");

    /* Create two veth pairs */
    ok = ok && run("ip link add ext type veth peer name %s", ext_ifname);
    ok = ok && run("ip link add int type veth peer name %s", int_ifname);

    /* Disable the loopback interface to allow us to use the 127.0.0.0/8 subnet */
    ok = ok && run("ip link set dev lo down");

    /* Configure MACs, IPs, and netmasks on the container side of each veth pair */
    ok = ok && run("ip link set dev ext up address %{mac}", &entry->value.external_mac);
    ok = ok && run("ip addr add %s/%s dev ext", external_ip, external_netmask);
    ok = ok && run("ip link set dev int up address %{mac}", &entry->value.internal_mac);
    ok = ok && run("ip addr add %s/%s dev int", internal_ip, internal_netmask);

    /* Create the default route to external_gateway */
    ok = ok && run("ip route add to default via %s", external_gateway_ip);

    /* Create the policy-based routing rule and route to internal_gateway */
    ok = ok && run("ip route add to default via %s table 1000", internal_gateway_ip);
    ok = ok && run("ip rule add priority 1 iif ext lookup 1000");

    /* Create static ARP entries for the internal and external gateways */
    ok = ok && run("ip neigh replace %s lladdr %{mac} nud permanent dev int", internal_gateway_ip, &entry->value.internal_gateway_mac);
    ok = ok && run("ip neigh replace %s lladdr %{mac} nud permanent dev ext", external_gateway_ip, &entry->value.external_gateway_mac);

    /* Setup iptables for NAT */
    ok = ok && run("iptables -t nat -A POSTROUTING -o ext -j SNAT --to-source %{ipv4a}", entry->key.external_ip);
    ok = ok && run("iptables -A FORWARD -i ext -m state --state RELATED,ESTABLISHED -j ACCEPT");
    ok = ok && run("iptables -A FORWARD -o ext -j ACCEPT");
    ok = ok && run("iptables -P FORWARD DROP");

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
nat_container_teardown(struct nat_entry *entry)
{
    close(entry->netns);
}


/* nat table operations */

static indigo_error_t
nat_parse_key(of_list_bsn_tlv_t *tlvs, struct nat_entry_key *key)
{
    of_bsn_tlv_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_IP) {
        of_bsn_tlv_external_ip_value_get(&tlv.external_ip, &key->external_ip);
    } else {
        AIM_LOG_ERROR("expected external_ip key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_parse_value(of_list_bsn_tlv_t *tlvs, struct nat_entry_value *value)
{
    of_bsn_tlv_t tlv;

    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External MAC */
    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_MAC) {
        of_bsn_tlv_external_mac_value_get(&tlv.external_mac, &value->external_mac);
    } else {
        AIM_LOG_ERROR("expected external_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External gateway MAC */
    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_GATEWAY_MAC) {
        of_bsn_tlv_external_gateway_mac_value_get(&tlv.external_gateway_mac, &value->external_gateway_mac);
    } else {
        AIM_LOG_ERROR("expected external_gateway_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal MAC */
    if (tlv.header.object_id == OF_BSN_TLV_INTERNAL_MAC) {
        of_bsn_tlv_internal_mac_value_get(&tlv.internal_mac, &value->internal_mac);
    } else {
        AIM_LOG_ERROR("expected internal_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal gateway MAC */
    if (tlv.header.object_id == OF_BSN_TLV_INTERNAL_GATEWAY_MAC) {
        of_bsn_tlv_internal_gateway_mac_value_get(&tlv.internal_gateway_mac, &value->internal_gateway_mac);
    } else {
        AIM_LOG_ERROR("expected internal_gateway_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.header.object_id]);
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
