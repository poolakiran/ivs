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

#include "pipeline_bvs_int.h"

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <indigo/port_manager.h>

#define NUM_OF_QUEUES 9

static bool port_tc_setup[SLSHARED_CONFIG_OF_PORT_MAX+1];

void
pipeline_bvs_setup_tc(char *ifname, of_port_no_t port_no)
{
    if (!strcmp(ifname, "local")) {
        /* There's no real interface named "local" so this would fail */
        return;
    }

    if (port_tc_setup[port_no] == true) {
        return;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        AIM_LOG_ERROR("if_nametoindex failed for %s", ifname);
        return;
    }

    int rv;
    struct nl_sock *sk = nl_socket_alloc();
    if (sk == NULL) {
        AIM_DIE("failed to allocate netlink socket");
    }

    if ((rv = nl_connect(sk, NETLINK_ROUTE)) < 0) {
        AIM_DIE("Failed to connect netlink socket: %s", nl_geterror(rv));
    }

    {
        struct nl_msg *msg = nlmsg_alloc_simple(RTM_DELQDISC, 0);
        struct tcmsg tcmsg = { 0 };
        tcmsg.tcm_family = AF_UNSPEC;
        tcmsg.tcm_ifindex = ifindex;
        tcmsg.tcm_parent = TC_H_ROOT;
        tcmsg.tcm_handle = TC_H_UNSPEC;
        nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
        if (nl_send_sync(sk, msg) < 0) {
            AIM_LOG_VERBOSE("nl_send_sync failed for %s, ignoring", ifname);
        }
    }

    {
        struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWQDISC, NLM_F_CREATE);
        struct tcmsg tcmsg = { 0 };
        tcmsg.tcm_family = AF_UNSPEC;
        tcmsg.tcm_ifindex = ifindex;
        tcmsg.tcm_parent = TC_H_ROOT;
        tcmsg.tcm_handle = TC_H_MAKE(1<<16, 0);
        nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
        nla_put_string(msg, TCA_KIND, "drr");
        if (nl_send_sync(sk, msg) < 0) {
            AIM_LOG_ERROR("nl_send_sync failed during adding root qdisc for %s", ifname);
            goto error;
        }
    }

    {
        struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWTFILTER, NLM_F_CREATE);
        struct tcmsg tcmsg = { 0 };
        tcmsg.tcm_family = AF_UNSPEC;
        tcmsg.tcm_ifindex = ifindex;
        tcmsg.tcm_parent = TC_H_MAKE(1<<16, 0);
        tcmsg.tcm_handle = 1;
        tcmsg.tcm_info = htons(ETH_P_ALL);
        nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
        nla_put_string(msg, TCA_KIND, "flow");
        struct nlattr *flow_offset = nla_nest_start(msg, TCA_OPTIONS);
        nla_put_u32(msg, TCA_FLOW_MODE, FLOW_MODE_MAP);
        nla_put_u32(msg, TCA_FLOW_KEYS, 1 << FLOW_KEY_PRIORITY);
        nla_nest_end(msg, flow_offset);
        if (nl_send_sync(sk, msg) < 0) {
            AIM_LOG_ERROR("nl_send_sync failed during adding filter for %s", ifname);
            goto error;
        }
    }

    int i;
    for (i = 0; i < NUM_OF_QUEUES; i++) {
        {
            struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWTCLASS, NLM_F_CREATE);
            struct tcmsg tcmsg = { 0 };
            tcmsg.tcm_family = AF_UNSPEC;
            tcmsg.tcm_ifindex = ifindex;
            tcmsg.tcm_parent = TC_H_MAKE(1<<16, 0);
            tcmsg.tcm_handle = TC_H_MAKE(1<<16, i+1);
            nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
            nla_put_string(msg, TCA_KIND, "drr");
            nla_put(msg, TCA_OPTIONS, 0, NULL);
            if (nl_send_sync(sk, msg) < 0) {
                AIM_LOG_ERROR("nl_send_sync failed during adding class %d for %s", i+1, ifname);
                goto error;
            }
        }

        {
            struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWQDISC, NLM_F_CREATE);
            struct tcmsg tcmsg = { 0 };
            tcmsg.tcm_family = AF_UNSPEC;
            tcmsg.tcm_ifindex = ifindex;
            tcmsg.tcm_parent = TC_H_MAKE(1<<16, i+1);
            tcmsg.tcm_handle = TC_H_MAKE((10+i) << 16, 0);
            nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
            if (i == QUEUE_PRIORITY_UNUSED_1 || i == QUEUE_PRIORITY_UNUSED_2 ||
                i == QUEUE_PRIORITY_PDU) {
                nla_put_string(msg, TCA_KIND, "pfifo");
                struct tc_fifo_qopt opt = { .limit=100 };
                nla_put(msg, TCA_OPTIONS, sizeof(opt), &opt);
            } else {
                nla_put_string(msg, TCA_KIND, "sfq");
            }
            if (nl_send_sync(sk, msg) < 0) {
                AIM_LOG_ERROR("nl_send_sync failed during adding qdisc to class %d for %s", i+1, ifname);
                goto error;
            }
        }
    }

    port_tc_setup[port_no] = true;

error:
    nl_socket_free(sk);
}

void
pipeline_bvs_qos_register(void)
{
    indigo_port_info_t *port_list, *port_info;
    if (indigo_port_interface_list(&port_list) < 0) {
        AIM_LOG_VERBOSE("Failed to retrieve port list");
        return;
    }

    for (port_info = port_list; port_info; port_info = port_info->next) {
        pipeline_bvs_setup_tc(port_info->port_name, port_info->of_port);
    }

    indigo_port_interface_list_destroy(port_list);
}
