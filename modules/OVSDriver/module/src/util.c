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
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h> /* for SIOCETHTOOL */
#include <linux/ethtool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

static indigo_error_t sys2indigoerr(int err);

#ifndef IND_OVS_NLMSG_MEMLEAK_DBG
/*
 * Allocating and freeing nlmsgs consumes a significant amount of CPU.
 * We know we'll never need more than a few nlmsgs at a time, so
 * preallocate them. This also makes it impossible for
 * ind_ovs_create_nlmsg to fail.
 */
#define IND_OVS_NLMSG_FREELIST_SIZE 8
static struct nl_msg *ind_ovs_nlmsg_freelist[IND_OVS_NLMSG_FREELIST_SIZE];
#endif /* IND_OVS_NLMSG_MEMLEAK_DBG */

DEBUG_COUNTER(netlink_transaction, "ovsdriver.util.netlink_transaction", "Netlink transaction");
DEBUG_COUNTER(netlink_send_failed, "ovsdriver.util.netlink_send_failed", "Netlink send failed");
DEBUG_COUNTER(netlink_recv_failed, "ovsdriver.util.netlink_recv_failed", "Netlink recv failed");
DEBUG_COUNTER(netlink_bad_error_number, "ovsdriver.util.netlink_bad_error_number", "Netlink error is out of range (kernel bug)");
DEBUG_COUNTER(netlink_error, "ovsdriver.util.netlink_error", "Received an error reply for a Netlink transaction");

uint32_t
get_entropy(void)
{
    const char *source = "/dev/urandom";

    FILE *f = fopen(source, "r");
    if (!f) {
        LOG_ERROR("failed to open %s", source);
        abort();
    }

    uint32_t v;
    if (fread(&v, sizeof(v), 1, f) != 1) {
        LOG_ERROR("failed to read %s", source);
        abort();
    }

    fclose(f);

    return v;
}

uint64_t
monotonic_us(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return ((uint64_t)tp.tv_sec * 1000*1000) + (tp.tv_nsec / 1000);
}

/* Send a netlink message and wait for an ack or error reply. */
int
ind_ovs_transact(struct nl_msg *msg)
{
    int ret = ind_ovs_transact_nofree(msg);
    ind_ovs_nlmsg_freelist_free(msg);
    return ret;
}

/* Doesn't free the sent message */
int
ind_ovs_transact_nofree(struct nl_msg *msg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    uint16_t family = nlh->nlmsg_type;
    uint8_t cmd = gnlh->cmd;

    debug_counter_inc(&netlink_transaction);

    LOG_VERBOSE("Running transaction:");
    ind_ovs_dump_msg(nlh);

    nlh->nlmsg_flags |= NLM_F_ACK;
    int err = nl_send_auto(ind_ovs_socket, msg);
#ifndef NDEBUG
    uint32_t seq = nlh->nlmsg_seq;
#endif
    if (err < 0) {
        debug_counter_inc(&netlink_send_failed);
        LOG_ERROR("nl_send failed: %s", nl_geterror(err));
        return INDIGO_ERROR_UNKNOWN;
    }

    struct nl_msg *reply_msg = ind_ovs_recv_nlmsg(ind_ovs_socket);
    if (reply_msg == NULL) {
        debug_counter_inc(&netlink_recv_failed);
        LOG_ERROR("ind_ovs_recv_nlmsg failed: %s", strerror(errno));
        return INDIGO_ERROR_UNKNOWN;
    }

    struct nlmsghdr *reply = nlmsg_hdr(reply_msg);
    assert(reply->nlmsg_type == NLMSG_ERROR);
    assert(reply->nlmsg_seq == seq);
    err = ((struct nlmsgerr *)nlmsg_data(reply))->error;
    ind_ovs_nlmsg_freelist_free(reply_msg);

    /*
     * HACK the OVS kernel module had a bug (fixed by rlane in d5c9288d) which
     * returned random values on success. Work around this by assuming the
     * operation was successful if the kernel returned an invalid errno.
     */
    if (err > 0 || err < -4095) {
        debug_counter_inc(&netlink_bad_error_number);
        err = 0;
    }

    static unsigned int ratelimited = 0;
    static bool first = true;
    static aim_ratelimiter_t ratelimiter;
    if (first) {
        aim_ratelimiter_init(&ratelimiter, 1000*1000, 2, NULL);
        first = false;
    }

    if (err < 0) {
        debug_counter_inc(&netlink_error);
        if (!aim_ratelimiter_limit(&ratelimiter, monotonic_us())) {
            AIM_LOG_WARN("Transaction failed (%s): %s",
                         ind_ovs_cmd_str(family, cmd), strerror(-err));
            ind_ovs_dump_msg_force(nlh);

            if (ratelimited) {
                AIM_LOG_WARN("%u other netlink transactions failed", ratelimited);
                ratelimited = 0;
            }
        } else {
            ratelimited++;
        }
        return sys2indigoerr(-err);
    }

    LOG_VERBOSE("Transaction successful");
    return INDIGO_ERROR_NONE;
}

/* Send a netlink message and wait for a reply msg or error reply. */
int
ind_ovs_transact_reply(struct nl_msg *msg, struct nlmsghdr **reply)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    uint16_t family = nlh->nlmsg_type;
    uint8_t cmd = gnlh->cmd;

    debug_counter_inc(&netlink_transaction);

    LOG_VERBOSE("Running transaction:");
    ind_ovs_dump_msg(nlmsg_hdr(msg));

    int err = nl_send_auto(ind_ovs_socket, msg);
#ifndef NDEBUG
    uint32_t seq = nlmsg_hdr(msg)->nlmsg_seq;
#endif
    ind_ovs_nlmsg_freelist_free(msg);
    if (err < 0) {
        debug_counter_inc(&netlink_send_failed);
        LOG_ERROR("nl_send failed: %s", nl_geterror(err));
        return INDIGO_ERROR_UNKNOWN;
    }

    struct sockaddr_nl nla;
    err = nl_recv(ind_ovs_socket, &nla, (unsigned char **)reply, NULL);
    if (err <= 0) {
        debug_counter_inc(&netlink_recv_failed);
        LOG_ERROR("nl_recv failed: %s", nl_geterror(err));
        return INDIGO_ERROR_UNKNOWN;
    }

    assert((*reply)->nlmsg_seq == seq);

    if ((*reply)->nlmsg_type == NLMSG_ERROR) {
        err = ((struct nlmsgerr *)nlmsg_data(*reply))->error;
        free(*reply);
        *reply = NULL;
        LOG_WARN("Transaction failed (%s): %s",
                 ind_ovs_cmd_str(family, cmd), strerror(-err));
        debug_counter_inc(&netlink_error);
        return sys2indigoerr(-err);
    }

    LOG_VERBOSE("Received reply:");
    ind_ovs_dump_msg(*reply);

    LOG_VERBOSE("Transaction successful");
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
sys2indigoerr(int err)
{
    switch (err) {
    case ENOENT: return INDIGO_ERROR_NOT_FOUND;
    case ENODEV: return INDIGO_ERROR_NOT_FOUND;
    default: return INDIGO_ERROR_UNKNOWN;
    }
}

/*
 * HACK
 *
 * libnl (as of 3.2.21) uses a bitmap to keep track of allocated netlink PIDs.
 * When a socket is freed in the main process its PID is marked as free and the
 * next netlink socket created may reuse that PID. This is a problem when
 * upcall processes still have references to the old socket. The kernel will
 * fail the bind() call for the new socket because the PID is in use.
 *
 * The kernel will assign a unique PID if we pass 0 in the call to bind().
 * This function allocates a PID using that feature. However, it is still not
 * ideal due to a race with other processes allocating PIDs. The race is
 * unlikely to happen in practice because the kernel does not recycle PIDs
 * quickly.
 */
static uint32_t
allocate_nl_pid()
{
    struct sockaddr_nl snl;
    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        AIM_DIE("Failed to allocate netlink pid: socket: %s", strerror(errno));
    }

    if (bind(fd, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
        AIM_DIE("Failed to allocate netlink pid: bind: %s", strerror(errno));
    }

    socklen_t len = sizeof(snl);
    if (getsockname(fd, (struct sockaddr *)&snl, &len) < 0) {
        AIM_DIE("Failed to allocate netlink pid: getsockname: %s", strerror(errno));
    }

    close(fd);

    return snl.nl_pid;
}

struct nl_sock *
ind_ovs_create_nlsock(void)
{
    int ret;

    struct nl_sock *sk = nl_socket_alloc();
    if (sk == NULL) {
        LOG_ERROR("failed to allocate netlink socket");
        return NULL;
    }

    nl_socket_set_local_port(sk, allocate_nl_pid());

    if ((ret = genl_connect(sk)) != 0) {
        LOG_ERROR("failed to connect netlink socket: %s", nl_geterror(ret));
        nl_socket_free(sk);
        return NULL;
    }

    nl_socket_disable_auto_ack(sk);

    nl_socket_set_nonblocking(sk);

    return sk;
}

/*
 * This function will not fail. Messages returned by it must be freed
 * with ind_ovs_nlmsg_freelist_free.
 */
struct nl_msg *
ind_ovs_create_nlmsg(int family, int cmd)
{
    int version;
    if (family == ovs_datapath_family) {
        version = OVS_DATAPATH_VERSION;
    } else if (family == ovs_packet_family) {
        version = OVS_PACKET_VERSION;
    } else if (family == ovs_vport_family) {
        version = OVS_VPORT_VERSION;
    } else if (family == ovs_flow_family) {
        version = OVS_FLOW_VERSION;
    } else {
        abort();
    }

    int flags = 0;

    struct nl_msg *msg = ind_ovs_nlmsg_freelist_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         family, sizeof(*hdr),
                                         flags, cmd, version);
    hdr->dp_ifindex = ind_ovs_dp_ifindex;

    return msg;
}

/*
 * Fast netlink recv.
 * Returned message must be freed with ind_ovs_nlmsg_freelist_free.
 */
struct nl_msg *
ind_ovs_recv_nlmsg(struct nl_sock *sk)
{
    int fd = nl_socket_get_fd(sk);
    struct nl_msg *msg = ind_ovs_nlmsg_freelist_alloc();
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    int n = read(fd, nlh, IND_OVS_DEFAULT_MSG_SIZE);
    /* TODO detect truncation */
    if (n < 0) {
        ind_ovs_nlmsg_freelist_free(msg);
        return NULL;
    }

    /* Workaround for a kernel bug. See comment in ind_ovs_handle_port_upcalls. */
    if (nlh->nlmsg_type == ovs_packet_family && nlh->nlmsg_len + nlmsg_padlen(nlh->nlmsg_len) != n) {
        nlh->nlmsg_len = n;
    }

    return msg;
}

/*
 * Wrap nla_nest_end, ensuring an attribute is created even if it would be
 * empty.
 */
void
ind_ovs_nla_nest_end(struct nl_msg *msg, struct nlattr *start)
{
    if (nlmsg_tail(nlmsg_hdr(msg)) == (start + 1)) {
        /* HACK OVS expects an empty nested attribute */
        /* Not technically legal netlink before 2.6.29 */
        assert(start->nla_len == NLA_HDRLEN);
        return;
    }

    nla_nest_end(msg, start);
}

void
ind_ovs_nlmsg_freelist_init(void)
{
#ifndef IND_OVS_NLMSG_MEMLEAK_DBG
    int i;
    for (i = 0; i < IND_OVS_NLMSG_FREELIST_SIZE; i++) {
        struct nl_msg *msg = nlmsg_alloc();
        if (msg == NULL) {
            LOG_ERROR("Failed to preallocate nlmsgs");
            abort();
        }
        ind_ovs_nlmsg_freelist[i] = msg;
    }
#endif /* IND_OVS_NLMSG_MEMLEAK_DBG */
}

void
ind_ovs_nlmsg_freelist_finish(void)
{
#ifndef IND_OVS_NLMSG_MEMLEAK_DBG
    int i;
    for (i = 0; i < IND_OVS_NLMSG_FREELIST_SIZE; i++) {
        struct nl_msg *msg = ind_ovs_nlmsg_freelist[i];
        if (msg != NULL) {
            nlmsg_free(msg);
            ind_ovs_nlmsg_freelist[i] = NULL;
        }
    }
#endif /* IND_OVS_NLMSG_MEMLEAK_DBG */
}

struct nl_msg *
ind_ovs_nlmsg_freelist_alloc(void)
{
#ifdef IND_OVS_NLMSG_MEMLEAK_DBG
    struct nl_msg *msg = nlmsg_alloc();
    if (msg != NULL) {
        return msg;
    }
#else  /* IND_OVS_NLMSG_MEMLEAK_DBG */
    int i;
    for (i = 0; i < IND_OVS_NLMSG_FREELIST_SIZE; i++) {
        struct nl_msg *msg = ind_ovs_nlmsg_freelist[i];
        if (msg != NULL) {
            ind_ovs_nlmsg_freelist[i] = NULL;
            return msg;
        }
    }
#endif /* IND_OVS_NLMSG_MEMLEAK_DBG */

    LOG_ERROR("Failed to allocate nlmsg, consider increasing IND_OVS_NLMSG_FREELIST_SIZE");
    abort();
}

void
ind_ovs_nlmsg_freelist_free(struct nl_msg *msg)
{
#ifndef IND_OVS_NLMSG_MEMLEAK_DBG
    int i;
    for (i = 0; i < IND_OVS_NLMSG_FREELIST_SIZE; i++) {
        if (ind_ovs_nlmsg_freelist[i] == NULL) {
            nlmsg_hdr(msg)->nlmsg_len = nlmsg_total_size(0);
            ind_ovs_nlmsg_freelist[i] = msg;
            return;
        } else if (ind_ovs_nlmsg_freelist[i] == msg) {
            AIM_DIE("netlink message already in the freelist");
        }
    }
#endif /* IND_OVS_NLMSG_MEMLEAK_DBG */

    nlmsg_free(msg);
}

/*
 * Execute an ioctl on a network device. See man 7 netdevice.
 * The ifr_name field in 'req' must be populated. Depending on
 * 'cmd' req will be read from or written to.
 */
static indigo_error_t
ind_ovs_interface_ioctl(long cmd, struct ifreq *req)
{
    static int sock = -1;
    if (sock < 0) {
        sock = socket(AF_PACKET, SOCK_RAW, 0);
        if (sock < 0) {
            return INDIGO_ERROR_UNKNOWN;
        }
    }

    if (ioctl(sock, cmd, req) < 0) {
        return sys2indigoerr(errno);
    } else {
        return INDIGO_ERROR_NONE;
    }
}

/*
 * Execute an eth ioctl on a network device. See man 7 netdevice.
 * The ifr_name field in 'req' must be populated. Depending on
 * 'cmd' req will be read from or written to.
 */
static indigo_error_t
ind_ovs_ethtool_ioctl(const char *ifname, void *ecmd)
{
    struct ifreq req;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    req.ifr_data = (void*)ecmd;
    return ind_ovs_interface_ioctl(SIOCETHTOOL, &req);
}

/*
 * Execute the SIOCGIFFLAGS ioctl on the given interface,
 * returning the result in '*flags' on success.
 */
indigo_error_t
ind_ovs_get_interface_flags(const char *ifname, int *flags)
{
    struct ifreq req;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    indigo_error_t err = ind_ovs_interface_ioctl(SIOCGIFFLAGS, &req);
    if (!err) {
        *flags = req.ifr_flags;
    }
    return err;
}

/*
 * Execute the SIOCSIFFLAGS ioctl on the given interface.
 */
indigo_error_t
ind_ovs_set_interface_flags(const char *ifname, int flags)
{
    struct ifreq req;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    req.ifr_flags = flags;
    return ind_ovs_interface_ioctl(SIOCSIFFLAGS, &req);
}

/*
 * Get the ofp_port_features bitsets for the given interface.
 */
void
ind_ovs_get_interface_features(const char *ifname,
                               uint32_t *curr, uint32_t *advertised,
                               uint32_t *supported, uint32_t *peer,
                               int version)
{
    struct ethtool_cmd ecmd = { 0 };

    *curr = 0;
    *advertised = 0;
    *supported = 0;
    *peer = 0;

    ecmd.cmd = ETHTOOL_GSET;
    indigo_error_t err = ind_ovs_ethtool_ioctl(ifname, &ecmd);
    if (err == INDIGO_ERROR_NOT_FOUND) {
        /* Virtual ports (gre, etc) don't support ethtool */
        *curr |= OF_PORT_FEATURE_FLAG_10GB_FD;
        *curr |= OF_PORT_FEATURE_FLAG_COPPER_BY_VERSION(version);
        return;
    } else if (err != INDIGO_ERROR_NONE) {
        LOG_ERROR("ethtool failed on interface %s: %s", ifname, strerror(errno));
        return;
    }

    uint32_t speed = ethtool_cmd_speed(&ecmd);
    if (ecmd.duplex == DUPLEX_FULL) {
        switch (speed) {
        case SPEED_10: *curr |= OF_PORT_FEATURE_FLAG_10MB_FD; break;
        case SPEED_100: *curr |= OF_PORT_FEATURE_FLAG_100MB_FD; break;
        case SPEED_1000: *curr |= OF_PORT_FEATURE_FLAG_1GB_FD; break;
        case SPEED_10000: *curr |= OF_PORT_FEATURE_FLAG_10GB_FD; break;
        }
    } else {
        switch (speed) {
        case SPEED_10: *curr |= OF_PORT_FEATURE_FLAG_10MB_HD; break;
        case SPEED_100: *curr |= OF_PORT_FEATURE_FLAG_100MB_HD; break;
        case SPEED_1000: *curr |= OF_PORT_FEATURE_FLAG_1GB_HD; break;
        }
    }

    if (ecmd.port == PORT_TP) {
        *curr |= OF_PORT_FEATURE_FLAG_COPPER_BY_VERSION(version);
    } else if (ecmd.port == PORT_FIBRE) {
        *curr |= OF_PORT_FEATURE_FLAG_FIBER_BY_VERSION(version);
    }

    if (ecmd.autoneg == AUTONEG_ENABLE) {
        *curr |= OF_PORT_FEATURE_FLAG_AUTONEG_BY_VERSION(version);
    }

    /* TODO advertised, supported, peer */
}

indigo_error_t
ind_ovs_set_ethtool_flags(const char *ifname, uint32_t flags, uint32_t mask)
{
    struct ethtool_value eval = { 0 };
    eval.cmd = ETHTOOL_GFLAGS;
    indigo_error_t err = ind_ovs_ethtool_ioctl(ifname, &eval);
    if (err < 0) {
        LOG_ERROR("failed to read ethtool flags: %s", indigo_strerror(err));
        return err;
    }

    uint32_t new_flags = (eval.data & ~mask) | flags;

    if (new_flags == eval.data) {
        return INDIGO_ERROR_NONE;
    }

    eval.cmd = ETHTOOL_SFLAGS;
    eval.data = new_flags;
    err = ind_ovs_ethtool_ioctl(ifname, &eval);
    if (err < 0) {
        LOG_ERROR("failed to set ethtool flags: %s", indigo_strerror(err));
        return err;
    }

    return INDIGO_ERROR_NONE;
}

indigo_error_t
ind_ovs_set_ethtool_gro(const char *ifname, bool enabled)
{
    struct ethtool_value eval = {
        .cmd = ETHTOOL_SGRO,
        .data = enabled,
    };

    indigo_error_t err = ind_ovs_ethtool_ioctl(ifname, &eval);
    if (err < 0) {
        LOG_ERROR("failed to %s GRO on %s: %s",
                  enabled ? "enable" : "disable", ifname, strerror(errno));
        return err;
    }

    return INDIGO_ERROR_NONE;
}

indigo_error_t
write_file(const char *filename, const char *str)
{
    int fd = open(filename, O_WRONLY);
    if (fd < 0) {
        AIM_LOG_ERROR("Failed to open file \"%s\": %s", filename, strerror(errno));
        return INDIGO_ERROR_UNKNOWN;
    }

    if (write(fd, str, strlen(str)) < 0) {
        AIM_LOG_ERROR("Failed to write to file \"%s\": %s", filename, strerror(errno));
        close(fd);
        return INDIGO_ERROR_UNKNOWN;
    }

    close(fd);
    return INDIGO_ERROR_NONE;
}

/*
 * Set MTU on given interface.
 */
indigo_error_t
ind_ovs_set_mtu(const char *ifname, int mtu)
{
    struct ifreq req;
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    req.ifr_mtu = mtu;
    return ind_ovs_interface_ioctl(SIOCSIFMTU, &req);
}
