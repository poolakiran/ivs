/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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
#include "ovsdriver_log.h"
#include "indigo/forwarding.h"
#include "indigo/port_manager.h"
#include "indigo/of_state_manager.h"
#include "SocketManager/socketmanager.h"
#include <errno.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

struct ind_ovs_port *ind_ovs_ports[IND_OVS_MAX_PORTS];  /**< Table of all ports */

static struct nl_sock *route_cache_sock;
static struct nl_cache_mngr *route_cache_mngr;
static struct nl_cache *link_cache;
static struct nl_cb *netlink_callbacks;

static indigo_error_t port_status_notify(uint32_t port_no, unsigned reason);
static void port_desc_set(of_port_desc_t *of_port_desc, of_port_no_t of_port_num);
static void alloc_port_counters(struct ind_ovs_port_counters *pcounters);
static void free_port_counters(struct ind_ovs_port_counters *pcounters);
static uint64_t get_packet_stats(struct stats_handle *handle);

aim_ratelimiter_t nl_cache_refill_limiter;

static struct ind_ovs_port_counters dummy_stats;

static void
ind_ovs_update_link_stats()
{
    if (aim_ratelimiter_limit(&nl_cache_refill_limiter, monotonic_us()) == 0) {
        /* Refresh statistics */
        nl_cache_refill(route_cache_sock, link_cache);
    }
}

struct ind_ovs_port *
ind_ovs_port_lookup(of_port_no_t port_no)
{
    if (port_no == OF_PORT_DEST_LOCAL) {
        return ind_ovs_ports[OVSP_LOCAL];
    }

    if (port_no >= IND_OVS_MAX_PORTS) {
        return NULL;
    }

    return ind_ovs_ports[port_no];
}

struct ind_ovs_port *
ind_ovs_port_lookup_by_name(const char *ifname)
{
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port && !strcmp(port->ifname, ifname)) {
            return port;
        }
    }
    return NULL;
}

uint32_t
ind_ovs_port_lookup_netlink(of_port_no_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return 0;
    }

    return nl_socket_get_local_port(port->pktin_socket);
}

/* TODO populate more fields of the port desc */
indigo_error_t indigo_port_features_get(
    of_features_reply_t *features)
{
    indigo_error_t      result             = INDIGO_ERROR_NONE;
    of_list_port_desc_t *of_list_port_desc = 0;
    of_port_desc_t      *of_port_desc      = 0;

    if (features->version >= OF_VERSION_1_3) {
        return INDIGO_ERROR_NONE;
    }

    if ((of_port_desc = of_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_port_desc = of_list_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_list_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i]) {
            port_desc_set(of_port_desc, i);
            /* TODO error handling */
            of_list_port_desc_append(of_list_port_desc, of_port_desc);
        }
    }

    if (LOXI_FAILURE(of_features_reply_ports_set(features,
                                                 of_list_port_desc
                                                 )
                     )
        ) {
        LOG_ERROR("of_features_reply_ports_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (of_list_port_desc)  of_list_port_desc_delete(of_list_port_desc);
    if (of_port_desc)       of_port_desc_delete(of_port_desc);

    return (result);
}

/*
 * This function just asks the datapath to add the port. If that succeeds we'll
 * get a OVS_VPORT_CMD_NEW multicast message. At that point ind_ovs_port_added
 * will create our own representation of the port. This is to support using
 * ovs-dpctl to add and remove ports.
 */
indigo_error_t indigo_port_interface_add(
    indigo_port_name_t port_name,
    of_port_no_t of_port,
    indigo_port_config_t *config)
{
    assert(of_port < IND_OVS_MAX_PORTS);
    assert(strlen(port_name) < 256);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_NEW);
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_NETDEV);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, port_name);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, of_port);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    return ind_ovs_transact(msg);
}

indigo_error_t 
indigo_port_interface_list(indigo_port_info_t** list)
{
    int i;
    indigo_port_info_t* head = NULL; 

    if(list == NULL) { 
        return INDIGO_ERROR_PARAM; 
    }

    for (i = IND_OVS_MAX_PORTS-1; i >= 0; i--) { 
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if(port != NULL) { 
            indigo_port_info_t* pi = aim_zmalloc(sizeof(*pi));
            strncpy(pi->port_name, port->ifname, sizeof(port->ifname)); 
            pi->of_port = i; 
            pi->next = head; 
            head = pi;
        }
    }
    *list = head; 
    return 0; 
}


void
indigo_port_interface_list_destroy(indigo_port_info_t* list)
{
    while(list) { 
        indigo_port_info_t* next = list->next; 
        aim_free(list);
        list = next; 
    }
}


void
ind_ovs_port_added(uint32_t port_no, const char *ifname, of_mac_addr_t mac_addr)
{
    indigo_error_t err;

    if (ind_ovs_ports[port_no]) {
        return;
    }

    struct ind_ovs_port *port = aim_zmalloc(sizeof(*port));

    strncpy(port->ifname, ifname, sizeof(port->ifname));
    port->dp_port_no = port_no;
    port->mac_addr = mac_addr;
    aim_ratelimiter_init(&port->upcall_log_limiter, 1000*1000, 5, NULL);
    aim_ratelimiter_init(&port->pktin_limiter, PORT_PKTIN_INTERVAL, PORT_PKTIN_BURST_SIZE, NULL);
    pthread_mutex_init(&port->quiesce_lock, NULL);
    pthread_cond_init(&port->quiesce_cvar, NULL);
    alloc_port_counters(&port->pcounters);

    port->notify_socket = ind_ovs_create_nlsock();
    if (port->notify_socket == NULL) {
        goto cleanup_port;
    }

    if (nl_socket_set_nonblocking(port->notify_socket) < 0) {
        LOG_ERROR("failed to set netlink socket nonblocking");
        goto cleanup_port;
    }

    port->pktin_socket = ind_ovs_create_nlsock();
    if (port->pktin_socket == NULL) {
        goto cleanup_port;
    }

    if (nl_socket_set_nonblocking(port->pktin_socket) < 0) {
        LOG_ERROR("failed to set netlink socket nonblocking");
        goto cleanup_port;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_SET);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port_no);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID,
                nl_socket_get_local_port(port->notify_socket));
    err = ind_ovs_transact(msg);
    if (err < 0) {
        LOG_ERROR("datapath failed to configure port %s", ifname);
        goto cleanup_port;
    }

    if (!ind_ovs_get_interface_flags(ifname, &port->ifflags)) {
        /* Bring interface up if not already */
        if (!(port->ifflags & IFF_UP)) {
            port->ifflags |= IFF_UP;
            (void) ind_ovs_set_interface_flags(ifname, port->ifflags);
        }
    } else {
        /* Not a netdev, fake the interface flags */
        port->ifflags = IFF_UP;
    }

    /* Ensure port is fully populated before publishing it. */
    __sync_synchronize();

    ind_ovs_ports[port_no] = port;

    if ((err = port_status_notify(port_no, OF_PORT_CHANGE_REASON_ADD)) < 0) {
        LOG_WARN("failed to notify controller of port addition");
        /* Can't cleanup the port because it's already visible to other
         * threads. */
    }

    ind_ovs_upcall_register(port);
    ind_ovs_pktin_register(port);
    LOG_INFO("Added port %s", port->ifname);
    ind_ovs_kflow_invalidate_all();
    return;

cleanup_port:
    assert(ind_ovs_ports[port_no] == NULL);
    if (port->notify_socket) {
        nl_socket_free(port->notify_socket);
    }
    if (port->pktin_socket) {
        nl_socket_free(port->pktin_socket);
    }
    free_port_counters(&port->pcounters);
    aim_free(port);
}

/*
 * ind_ovs_port_deleted will free the port struct.
 */
indigo_error_t indigo_port_interface_remove(
    indigo_port_name_t port_name)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(port_name);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_DEL);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port->dp_port_no);
    return ind_ovs_transact(msg);
}

void
ind_ovs_port_deleted(uint32_t port_no)
{
    assert(port_no < IND_OVS_MAX_PORTS);
    struct ind_ovs_port *port = ind_ovs_ports[port_no];
    if (port == NULL) {
        return;
    }

    ind_ovs_pktin_register(port);
    ind_ovs_upcall_quiesce(port);
    ind_ovs_upcall_unregister(port);

    if (port_status_notify(port_no, OF_PORT_CHANGE_REASON_DELETE) < 0) {
        LOG_ERROR("failed to notify controller of port deletion");
    }

    LOG_INFO("Deleted port %s", port->ifname);

    ind_ovs_fwd_write_lock();
    nl_socket_free(port->notify_socket);
    nl_socket_free(port->pktin_socket);
    pthread_mutex_destroy(&port->quiesce_lock);
    pthread_cond_destroy(&port->quiesce_cvar);
    free_port_counters(&port->pcounters);
    aim_free(port);
    ind_ovs_ports[port_no] = NULL;
    ind_ovs_fwd_write_unlock();

    ind_ovs_kflow_invalidate_all();
}

indigo_error_t
indigo_port_modify(of_port_mod_t *port_mod)
{
    of_port_no_t port_no;
    of_port_mod_port_no_get(port_mod, &port_no);
    uint32_t config;
    of_port_mod_config_get(port_mod, &config);
    uint32_t mask;
    of_port_mod_mask_get(port_mod, &mask);

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    if (OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(mask, port_mod->version)) {
        port->no_packet_in = OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(config, port_mod->version);
    }

    if (OF_PORT_CONFIG_FLAG_NO_FLOOD_TEST(mask, port_mod->version)) {
        port->no_flood = OF_PORT_CONFIG_FLAG_NO_FLOOD_TEST(config, port_mod->version);
    }

    if (OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(mask, port_mod->version)) {
        port->admin_down = OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(config, port_mod->version);
        if (port->admin_down) {
            port->ifflags &= ~IFF_UP;
        } else {
            port->ifflags |= IFF_UP;
        }
        (void) ind_ovs_set_interface_flags(port->ifname, port->ifflags);
    }

    /* TODO change other configuration? */
    ind_ovs_kflow_invalidate_all();

    return INDIGO_ERROR_NONE;
}

static int
port_stats_iterator(struct nl_msg *msg, void *arg)
{
    of_list_port_stats_entry_t *list = arg;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[OVS_VPORT_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                    attrs, OVS_VPORT_ATTR_MAX,
                    NULL) < 0) {
        abort();
    }
    assert(attrs[OVS_VPORT_ATTR_PORT_NO]);
    assert(attrs[OVS_VPORT_ATTR_STATS]);

    uint32_t port_no = nla_get_u32(attrs[OVS_VPORT_ATTR_PORT_NO]);
    char *ifname = nla_get_string(attrs[OVS_VPORT_ATTR_NAME]);
    uint32_t vport_type = nla_get_u32(attrs[OVS_VPORT_ATTR_TYPE]);
    struct ovs_vport_stats *port_stats = nla_data(attrs[OVS_VPORT_ATTR_STATS]);

    of_port_stats_entry_t entry[1];
    of_port_stats_entry_init(entry, list->version, -1, 1);
    if (of_list_port_stats_entry_append_bind(list, entry) < 0) {
        /* TODO needs fix in indigo core */
        LOG_ERROR("too many port stats replies");
        return NL_STOP;
    }

    if (port_no == OVSP_LOCAL) {
        of_port_stats_entry_port_no_set(entry, OF_PORT_DEST_LOCAL);
    } else {
        of_port_stats_entry_port_no_set(entry, port_no);
    }

    struct rtnl_link *link;
    if ((vport_type == OVS_VPORT_TYPE_NETDEV
        || vport_type == OVS_VPORT_TYPE_INTERNAL)
        && (link = rtnl_link_get_by_name(link_cache, ifname))) {
        /* Get interface stats from NETLINK_ROUTE */
        of_port_stats_entry_rx_packets_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS));
        of_port_stats_entry_tx_packets_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS));
        of_port_stats_entry_rx_bytes_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES));
        of_port_stats_entry_tx_bytes_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES));
        of_port_stats_entry_rx_dropped_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED));
        of_port_stats_entry_tx_dropped_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED));
        of_port_stats_entry_rx_errors_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS));
        of_port_stats_entry_tx_errors_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS));
        of_port_stats_entry_rx_frame_err_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_FRAME_ERR));
        of_port_stats_entry_rx_over_err_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_OVER_ERR));
        of_port_stats_entry_rx_crc_err_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_RX_CRC_ERR));
        of_port_stats_entry_collisions_set(entry,
            rtnl_link_get_stat(link, RTNL_LINK_COLLISIONS));
        rtnl_link_put(link);
    } else {
        /* Use more limited stats from the datapath */
        of_port_stats_entry_rx_packets_set(entry, port_stats->rx_packets);
        of_port_stats_entry_tx_packets_set(entry, port_stats->tx_packets);
        of_port_stats_entry_rx_bytes_set(entry, port_stats->rx_bytes);
        of_port_stats_entry_tx_bytes_set(entry, port_stats->tx_bytes);
        of_port_stats_entry_rx_dropped_set(entry, port_stats->rx_dropped);
        of_port_stats_entry_tx_dropped_set(entry, port_stats->tx_dropped);
        of_port_stats_entry_rx_errors_set(entry, port_stats->rx_errors);
        of_port_stats_entry_tx_errors_set(entry, port_stats->tx_errors);
        of_port_stats_entry_rx_frame_err_set(entry, 0);
        of_port_stats_entry_rx_over_err_set(entry, 0);
        of_port_stats_entry_rx_crc_err_set(entry, 0);
        of_port_stats_entry_collisions_set(entry, 0);
    }

    return NL_OK;
}

void
indigo_port_extended_stats_get(
    of_port_no_t port_no,
    indigo_fi_port_stats_t *port_stats)
{
    AIM_ASSERT(port_stats != NULL);

    if (port_no == OF_PORT_DEST_LOCAL) {
        return;
    }

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return;
    }

    ind_ovs_update_link_stats();

    struct rtnl_link *link;
    if ((link = rtnl_link_get_by_name(link_cache, port->ifname))) {
        port_stats->rx_bytes = rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES);
        port_stats->rx_dropped = rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED);
        port_stats->rx_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS);
        port_stats->tx_bytes = rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES);
        port_stats->tx_dropped = rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED);
        port_stats->tx_errors = rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS);
        port_stats->rx_alignment_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_FRAME_ERR);
        port_stats->rx_crc_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_CRC_ERR);
        port_stats->tx_collisions = rtnl_link_get_stat(link, RTNL_LINK_COLLISIONS);
        port_stats->rx_packets = rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS);
        port_stats->tx_packets = rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS);
        port_stats->rx_length_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_LEN_ERR);
        port_stats->rx_overflow_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_OVER_ERR);
        port_stats->tx_carrier_errors = rtnl_link_get_stat(link, RTNL_LINK_TX_CARRIER_ERR);

        rtnl_link_put(link);

        port_stats->rx_packets_unicast = get_packet_stats(&port->pcounters.rx_unicast_stats_handle);
        port_stats->rx_packets_broadcast = get_packet_stats(&port->pcounters.rx_broadcast_stats_handle);
        port_stats->rx_packets_multicast = get_packet_stats(&port->pcounters.rx_multicast_stats_handle);
        port_stats->tx_packets_unicast = get_packet_stats(&port->pcounters.tx_unicast_stats_handle);
        port_stats->tx_packets_broadcast = get_packet_stats(&port->pcounters.tx_broadcast_stats_handle);
        port_stats->tx_packets_multicast = get_packet_stats(&port->pcounters.tx_multicast_stats_handle);
    }
}

indigo_error_t
indigo_port_stats_get(
    of_port_stats_request_t *port_stats_request,
    of_port_stats_reply_t **port_stats_reply_ptr)
{
    of_port_no_t req_of_port_num;
    of_port_stats_reply_t *port_stats_reply;
    indigo_error_t err = INDIGO_ERROR_NONE;

    port_stats_reply = of_port_stats_reply_new(port_stats_request->version);
    if (port_stats_reply == NULL) {
        err = INDIGO_ERROR_RESOURCE;
        goto out;
    }

    of_list_port_stats_entry_t list;
    of_port_stats_reply_entries_bind(port_stats_reply, &list);

    of_port_stats_request_port_no_get(port_stats_request, &req_of_port_num);
    int dump_all = req_of_port_num == OF_PORT_DEST_NONE_BY_VERSION(port_stats_request->version);

    ind_ovs_update_link_stats();

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_GET);
    if (dump_all) {
        nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;
    } else {
        nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, req_of_port_num);
    }

    /* Ask kernel to send us one or more OVS_VPORT_CMD_NEW messages */
    if (nl_send_auto(ind_ovs_socket, msg) < 0) {
        err = INDIGO_ERROR_UNKNOWN;
        goto out;
    }
    ind_ovs_nlmsg_freelist_free(msg);

    /* Handle OVS_VPORT_CMD_NEW messages */
    nl_cb_set(netlink_callbacks, NL_CB_VALID, NL_CB_CUSTOM,
              port_stats_iterator, &list);
    if (nl_recvmsgs(ind_ovs_socket, netlink_callbacks) < 0) {
        err = INDIGO_ERROR_UNKNOWN;
        goto out;
    }

out:
    if (err != INDIGO_ERROR_NONE) {
        of_port_stats_reply_delete(port_stats_reply);
        port_stats_reply = NULL;
    }

    *port_stats_reply_ptr = port_stats_reply;
    return err;
}

indigo_error_t indigo_port_desc_stats_get(
    of_port_desc_stats_reply_t *port_desc_stats_reply)
{
    indigo_error_t result = INDIGO_ERROR_NONE;

    of_port_desc_t *of_port_desc = 0;
    of_list_port_desc_t *of_list_port_desc = 0;

    if (port_desc_stats_reply->version < OF_VERSION_1_3) {
        return INDIGO_ERROR_NONE;
    }

    if ((of_port_desc = of_port_desc_new(port_desc_stats_reply->version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_port_desc = of_list_port_desc_new(port_desc_stats_reply->version)) == 0) {
        LOG_ERROR("of_list_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i]) {
            port_desc_set(of_port_desc, i);
            /* TODO error handling */
            of_list_port_desc_append(of_list_port_desc, of_port_desc);
        }
    }

    if (LOXI_FAILURE(of_port_desc_stats_reply_entries_set(port_desc_stats_reply,
            of_list_port_desc))){
        LOG_ERROR("of_port_desc_stats_reply_entries_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (of_list_port_desc) of_list_port_desc_delete(of_list_port_desc);
    if (of_port_desc) of_port_desc_delete(of_port_desc);

    return (result);
}

/* Currently returns an empty reply */
indigo_error_t
indigo_port_queue_config_get(
    of_queue_get_config_request_t *request,
    of_queue_get_config_reply_t **reply_ptr)
{
    of_queue_get_config_reply_t *reply;

    reply = of_queue_get_config_reply_new(request->version);
    if (reply == NULL) {
        LOG_ERROR("Could not allocate queue config reply");
        return INDIGO_ERROR_RESOURCE;
    }

    *reply_ptr = reply;
    return INDIGO_ERROR_NONE;
}

/* Currently returns an empty reply */
indigo_error_t
indigo_port_queue_stats_get(
    of_queue_stats_request_t *queue_stats_request,
    of_queue_stats_reply_t **queue_stats_reply_ptr)
{
    of_queue_stats_reply_t *queue_stats_reply = of_queue_stats_reply_new(queue_stats_request->version);
    if (queue_stats_reply == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    uint32_t xid;
    of_queue_stats_request_xid_get(queue_stats_request, &xid);
    of_queue_stats_reply_xid_set(queue_stats_reply, xid);

    *queue_stats_reply_ptr = queue_stats_reply;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_status_notify(uint32_t port_no, unsigned reason)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    of_port_desc_t   *of_port_desc   = 0;
    of_port_status_t *of_port_status = 0;
    of_version_t ctrlr_of_version;

    if (indigo_cxn_get_async_version(&ctrlr_of_version) != INDIGO_ERROR_NONE) {
        LOG_TRACE("No active controller connection");
        return INDIGO_ERROR_NONE;
    }

    if ((of_port_desc = of_port_desc_new(ctrlr_of_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    port_desc_set(of_port_desc, port_no);

    if ((of_port_status = of_port_status_new(ctrlr_of_version)) == 0) {
        LOG_ERROR("of_port_status_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_port_status_reason_set(of_port_status, reason);
    of_port_status_desc_set(of_port_status, of_port_desc);
    of_port_desc_delete(of_port_desc);

    indigo_core_port_status_update(of_port_status);

    of_port_desc   = 0;     /* No longer owned */
    of_port_status = 0;     /* No longer owned */

 done:
    if (of_port_desc)    of_port_desc_delete(of_port_desc);
    if (of_port_status)  of_port_status_delete(of_port_status);

    return (result);
}

static void
port_desc_set(of_port_desc_t *of_port_desc, uint32_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_ports[port_no];
    assert(port != NULL);

    if (port_no == OVSP_LOCAL) {
        of_port_desc_port_no_set(of_port_desc, OF_PORT_DEST_LOCAL);
    } else {
        of_port_desc_port_no_set(of_port_desc, port_no);
    }

    of_port_desc_hw_addr_set(of_port_desc, port->mac_addr);
    of_port_desc_name_set(of_port_desc, port->ifname);

    uint32_t config = 0;
    if (port->no_packet_in) {
        OF_PORT_CONFIG_FLAG_NO_PACKET_IN_SET(config, of_port_desc->version);
    }
    if (port->no_flood) {
        OF_PORT_CONFIG_FLAG_NO_FLOOD_SET(config, of_port_desc->version);
    }
    if (port->admin_down) {
        OF_PORT_CONFIG_FLAG_PORT_DOWN_SET(config, of_port_desc->version);
    }
    of_port_desc_config_set(of_port_desc, config);

    uint32_t state = 0;
    if (!(port->ifflags & IFF_RUNNING)) {
        state |= OF_PORT_STATE_FLAG_LINK_DOWN;
    }
    of_port_desc_state_set(of_port_desc, state);

    uint32_t curr, advertised, supported, peer;

    if (port_no == OVSP_LOCAL) {
        /* Internal ports do not support ethtool */
        curr = OF_PORT_FEATURE_FLAG_10GB_FD |
               OF_PORT_FEATURE_FLAG_COPPER_BY_VERSION(of_port_desc->version);
        advertised = 0;
        supported = 0;
        peer = 0;
    } else {
        ind_ovs_get_interface_features(port->ifname, &curr, &advertised,
            &supported, &peer, of_port_desc->version);
    }

    of_port_desc_curr_set(of_port_desc, curr);
    of_port_desc_advertised_set(of_port_desc, advertised);
    of_port_desc_supported_set(of_port_desc, supported);
    of_port_desc_peer_set(of_port_desc, peer);
}

/*
 * Called by nl_cache_mngr_data_ready if a link object changed.
 *
 * Sends a port status message to the controller.
 */
static void
link_change_cb(struct nl_cache *cache,
               struct nl_object *obj,
               int action,
               void *arg)
{
    struct rtnl_link *link = (struct rtnl_link *) obj;
    const char *ifname = rtnl_link_get_name(link);
    int ifflags = rtnl_link_get_flags(link);

    /*
     * Ignore additions/deletions, already handled by
     * ind_ovs_handle_vport_multicast.
     */
    if (action != 5 /* NL_ACT_CHANGE */) {
        return;
    }

    /* Ignore interfaces not connected to our datapath. */
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(ifname);
    if (port == NULL) {
        return;
    }

    /* Log at INFO only if the interface transitioned between up/down */
    if ((ifflags & IFF_RUNNING) && !(port->ifflags & IFF_RUNNING)) {
        LOG_INFO("Interface %s state changed to up", ifname);
    } else if (!(ifflags & IFF_RUNNING) && (port->ifflags & IFF_RUNNING)) {
        LOG_INFO("Interface %s state changed to down", ifname);
    }

    LOG_VERBOSE("Sending port status change notification for interface %s", ifname);

    port->ifflags = ifflags;
    port->admin_down = !(ifflags & IFF_UP);
    port_status_notify(port->dp_port_no, OF_PORT_CHANGE_REASON_MODIFY);
}

static void
route_cache_mngr_socket_cb(void)
{
    nl_cache_mngr_data_ready(route_cache_mngr);
}

void
ind_ovs_port_init(void)
{
    int nlerr;

    route_cache_sock = nl_socket_alloc();
    if (route_cache_sock == NULL) {
        LOG_ERROR("nl_socket_alloc failed");
        abort();
    }

    if ((nlerr = nl_cache_mngr_alloc(route_cache_sock, NETLINK_ROUTE,
                                     0, &route_cache_mngr)) < 0) {
        LOG_ERROR("nl_cache_mngr_alloc failed: %s", nl_geterror(nlerr));
        abort();
    }

    if ((nlerr = nl_cache_mngr_add(route_cache_mngr, "route/link", link_change_cb, NULL, &link_cache)) < 0) {
        LOG_ERROR("nl_cache_mngr_add failed: %s", nl_geterror(nlerr));
        abort();
    }

    if (ind_soc_socket_register(nl_cache_mngr_get_fd(route_cache_mngr),
                                (ind_soc_socket_ready_callback_f)route_cache_mngr_socket_cb,
                                NULL) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }

    netlink_callbacks = nl_cb_alloc(NL_CB_DEFAULT);
    if (netlink_callbacks == NULL) {
        LOG_ERROR("failed to allocate netlink callbacks");
        abort();
    }

    aim_ratelimiter_init(&nl_cache_refill_limiter, 1000*1000, 0, NULL);
}

void
ind_ovs_port_finish(void)
{
        ind_soc_socket_unregister(nl_cache_mngr_get_fd(route_cache_mngr));
        nl_cache_mngr_free(route_cache_mngr);
        nl_socket_free(route_cache_sock);
}

struct ind_ovs_port_counters *
ind_ovs_port_stats_select(of_port_no_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return &dummy_stats;
    }

    return &port->pcounters;
}

static void
alloc_port_counters(struct ind_ovs_port_counters *pcounters)
{
    stats_alloc(&pcounters->rx_unicast_stats_handle);
    stats_alloc(&pcounters->tx_unicast_stats_handle);
    stats_alloc(&pcounters->rx_broadcast_stats_handle);
    stats_alloc(&pcounters->tx_broadcast_stats_handle);
    stats_alloc(&pcounters->rx_multicast_stats_handle);
    stats_alloc(&pcounters->tx_multicast_stats_handle);
}

static void
free_port_counters(struct ind_ovs_port_counters *pcounters)
{
    stats_free(&pcounters->rx_unicast_stats_handle);
    stats_free(&pcounters->tx_unicast_stats_handle);
    stats_free(&pcounters->rx_broadcast_stats_handle);
    stats_free(&pcounters->tx_broadcast_stats_handle);
    stats_free(&pcounters->rx_multicast_stats_handle);
    stats_free(&pcounters->tx_multicast_stats_handle);
}

static uint64_t
get_packet_stats(struct stats_handle *handle)
{
    struct stats stats;
    stats_get(handle, &stats);
    return stats.packets;
}
