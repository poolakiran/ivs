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

#include "t6_pipeline_support.h"
#include <murmur/murmur.h>

#define AIM_LOG_MODULE_NAME pipeline
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT|AIM_LOG_BIT_VERBOSE, NULL, 0);

#define FORMAT_MAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define VALUE_MAC(a) (a)[0],(a)[1],(a)[2],(a)[3],(a)[4],(a)[5]
#define FORMAT_IPV4 "%hhu.%hhu.%hhu.%hhu"
#define VALUE_IPV4(a) (a)[0],(a)[1],(a)[2],(a)[3]

/* TODO add group lookup interface to pipeline struct in mainline */
indigo_error_t ind_ovs_group_select(uint32_t, uint32_t, struct xbuf **);

struct pipeline {
    int openflow_version;
    pipeline_lookup_f lookup;
};

enum table_id {
    TABLE_ID_L2 = 0,
    TABLE_ID_VLAN = 1,
    TABLE_ID_PORT = 2,
    TABLE_ID_VLAN_XLATE = 3,
    TABLE_ID_EGR_VLAN_XLATE = 4,
    TABLE_ID_MY_STATION = 5,
    TABLE_ID_L3_HOST_ROUTE = 6,
    TABLE_ID_L3_CIDR_ROUTE = 7,
    TABLE_ID_FLOOD = 11,
};

static const bool flood_on_dlf = true;

static indigo_error_t process_l3(struct pipeline *pipeline, struct ind_ovs_cfr *cfr, uint32_t hash, struct pipeline_result *result);
static indigo_error_t lookup_l2(struct pipeline *pipeline, uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no, uint32_t *group_id);
static indigo_error_t check_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, bool *tagged, uint32_t *vrf, bool *global_vrf_allowed);
static bool is_vlan_configured(struct pipeline *pipeline, uint16_t vlan_vid);
static indigo_error_t flood_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash, struct pipeline_result *result);
static indigo_error_t lookup_port(struct pipeline *pipeline, uint32_t port_no, uint16_t *default_vlan_vid, uint32_t *lag_id, bool *disable_src_mac_check);
static indigo_error_t lookup_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint32_t lag_id, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t select_lag_port(struct pipeline *pipeline, uint32_t group_id, uint32_t hash, uint32_t *port_no);
static indigo_error_t lookup_my_station(struct pipeline *pipeline, const uint8_t *eth_addr);
static indigo_error_t lookup_l3_route(struct pipeline *pipeline, uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, bool global_vrf_allowed, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *out_port);
static indigo_error_t lookup_l3_host_route(struct pipeline *pipeline, uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *out_port);
static indigo_error_t lookup_l3_cidr_route(struct pipeline *pipeline, uint32_t hash, uint32_t vrf, uint32_t ipv4_dst, of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst, uint16_t *new_vlan_vid, uint32_t *out_port);

indigo_error_t
t6_pipeline_process(struct pipeline *pipeline,
                    struct ind_ovs_cfr *cfr,
                    struct pipeline_result *result)
{
    uint32_t hash = murmur_hash(cfr, sizeof(*cfr), 0);

    if (cfr->dl_type == htons(0x88cc) || cfr->dl_type == htons(0x8809)) {
        AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(cfr->dl_type));
        pktin(result, OF_PACKET_IN_REASON_ACTION);
        return INDIGO_ERROR_NONE;
    }

    uint16_t default_vlan_vid;
    uint32_t lag_id;
    bool disable_src_mac_check;
    if (lookup_port(pipeline, cfr->in_port, &default_vlan_vid, &lag_id, &disable_src_mac_check) < 0) {
        AIM_LOG_WARN("port %u not found", cfr->in_port);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in port table lookup, default_vlan_vid=%u lag_id=%u", default_vlan_vid, lag_id);

    uint16_t vlan_vid;
    if (cfr->dl_vlan & htons(VLAN_CFI_BIT)) {
        vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan));
        uint16_t new_vlan_vid;
        if (lookup_vlan_xlate(pipeline, cfr->in_port, lag_id, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    } else {
        vlan_vid = default_vlan_vid;
        push_vlan(result, 0x8100);
        set_vlan_vid(result, vlan_vid);
    }

    /* Generate packet-in if packet received on unconfigured VLAN */
    if (is_vlan_configured(pipeline, vlan_vid) == false) {
        AIM_LOG_VERBOSE("Packet received on unconfigured vlan %u (bad VLAN)", vlan_vid);
        pktin(result, BSN_PACKET_IN_REASON_BAD_VLAN);
        return INDIGO_ERROR_NONE;
    }

    UNUSED bool in_port_tagged;
    bool global_vrf_allowed;
    uint32_t vrf;
    if (check_vlan(pipeline, vlan_vid, cfr->in_port, &in_port_tagged, &vrf, &global_vrf_allowed) < 0) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", cfr->in_port, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("VLAN %u: vrf=%u global_vrf_allowed=%d", vlan_vid, vrf, global_vrf_allowed);
    cfr->vrf = vrf;
    cfr->global_vrf_allowed = global_vrf_allowed;

    if (!disable_src_mac_check) {
        /* Source lookup */
        uint32_t src_port_no, src_group_id;
        if (lookup_l2(pipeline, vlan_vid, cfr->dl_src, &src_port_no, &src_group_id) < 0) {
            AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
            pktin(result, BSN_PACKET_IN_REASON_NEW_HOST);
            return INDIGO_ERROR_NONE;
        }

        AIM_LOG_VERBOSE("hit in source l2table lookup, src_port_no=%u src_group_id=%u", src_port_no, src_group_id);

        if (src_port_no != OF_PORT_DEST_NONE && src_port_no != cfr->in_port) {
            AIM_LOG_VERBOSE("incorrect port in source l2table lookup (station move)");
            pktin(result, BSN_PACKET_IN_REASON_STATION_MOVE);
            return INDIGO_ERROR_NONE;
        } else if (src_group_id != OF_GROUP_ANY && src_group_id != lag_id) {
            AIM_LOG_VERBOSE("incorrect lag_id in source l2table lookup (station move)");
            pktin(result, BSN_PACKET_IN_REASON_STATION_MOVE);
            return INDIGO_ERROR_NONE;
        }
    }

    /* Check for broadcast/multicast */
    if (cfr->dl_dst[0] & 1) {
        if (flood_vlan(pipeline, vlan_vid, cfr->in_port, lag_id, hash, result) < 0) {
            AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }
        return INDIGO_ERROR_NONE;
    }

    if (lookup_my_station(pipeline, cfr->dl_dst) == 0) {
        AIM_LOG_VERBOSE("hit in MyStation table, entering L3 processing");
        return process_l3(pipeline, cfr, hash, result);
    }

    /* Destination lookup */
    uint32_t dst_port_no, dst_group_id;
    if (lookup_l2(pipeline, vlan_vid, cfr->dl_dst, &dst_port_no, &dst_group_id) < 0) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");
        if (flood_on_dlf) {
            if (flood_vlan(pipeline, vlan_vid, cfr->in_port, lag_id, hash, result) < 0) {
                AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
            }
        } else {
            pktin(result, BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE);
        }
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in destination l2table lookup, dst_port_no=%u dst_group_id=%u", dst_port_no, dst_group_id);

    if (dst_group_id != OF_GROUP_ANY) {
        if (select_lag_port(pipeline, dst_group_id, hash, &dst_port_no) < 0) {
            return INDIGO_ERROR_NONE;
        }
        AIM_LOG_VERBOSE("selected LAG port %u", dst_port_no);
    }

    bool out_port_tagged;
    UNUSED bool out_global_vrf_allowed;
    UNUSED uint32_t out_vrf;
    if (check_vlan(pipeline, vlan_vid, dst_port_no, &out_port_tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
        AIM_LOG_WARN("output port %u not allowed on vlan %u", dst_port_no, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    if (!out_port_tagged) {
        pop_vlan(result);
    } else {
        uint16_t new_vlan_vid;
        if (lookup_egr_vlan_xlate(pipeline, dst_port_no, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    }

    output(result, dst_port_no);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
process_l3(struct pipeline *pipeline,
           struct ind_ovs_cfr *cfr,
           uint32_t hash,
           struct pipeline_result *result)
{
    of_mac_addr_t new_eth_src;
    of_mac_addr_t new_eth_dst;
    uint16_t new_vlan_vid;
    uint32_t lag_id;

    if (lookup_l3_route(pipeline, hash, cfr->vrf, cfr->nw_dst, cfr->global_vrf_allowed,
                        &new_eth_src, &new_eth_dst, &new_vlan_vid, &lag_id) < 0) {
        AIM_LOG_VERBOSE("no route to host");
        pktin(result, BSN_PACKET_IN_REASON_NO_ROUTE);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("next-hop: eth_src="FORMAT_MAC" eth_dst="FORMAT_MAC" vlan=%u lag_id=%u",
                    VALUE_MAC(new_eth_src.addr), VALUE_MAC(new_eth_dst.addr), new_vlan_vid, lag_id);

    uint32_t out_port;
    if (select_lag_port(pipeline, lag_id, hash, &out_port) < 0) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    AIM_LOG_VERBOSE("selected LAG port %u", out_port);

    bool out_port_tagged;
    UNUSED bool out_global_vrf_allowed;
    UNUSED uint32_t out_vrf;
    if (check_vlan(pipeline, new_vlan_vid, out_port, &out_port_tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
        AIM_LOG_WARN("output port %u not allowed on vlan %u", out_port, new_vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    if (!out_port_tagged) {
        pop_vlan(result);
    } else {
        lookup_egr_vlan_xlate(pipeline, out_port, new_vlan_vid, &new_vlan_vid);
        set_vlan_vid(result, new_vlan_vid);
    }

    set_eth_src(result, new_eth_src);
    set_eth_dst(result, new_eth_dst);
    dec_nw_ttl(result);
    output(result, out_port);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l2(struct pipeline *pipeline, uint16_t vlan_vid, const uint8_t *eth_addr,
          uint32_t *port_no, uint32_t *group_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    *port_no = OF_PORT_DEST_NONE;
    *group_id = OF_GROUP_ANY;

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);
    memcpy(&cfr.dl_dst, eth_addr, sizeof(cfr.dl_dst));

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_L2, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            *port_no = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *group_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static bool
is_vlan_configured(struct pipeline *pipeline, uint16_t vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_VLAN, &cfr, NULL);
    if (effects != NULL) {
        return true;
    }

    return false;
}

static indigo_error_t
check_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port,
           bool *tagged, uint32_t *vrf, bool *global_vrf_allowed)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_VLAN, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *tagged = true;
    *vrf = 0;
    *global_vrf_allowed = false;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            uint32_t port_no = *XBUF_PAYLOAD(attr, uint32_t);
            if (port_no == in_port) {
                return INDIGO_ERROR_NONE;
            }
        } else if (attr->nla_type == IND_OVS_ACTION_POP_VLAN) {
            *tagged = false;
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VRF) {
            *vrf = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_GLOBAL_VRF_ALLOWED) {
            *global_vrf_allowed = *XBUF_PAYLOAD(attr, uint8_t);
        }
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
flood_vlan(struct pipeline *pipeline,
           uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash,
           struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.lag_id = lag_id;

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_FLOOD, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    uint16_t tag = vlan_vid;
    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT ||
                attr->nla_type == IND_OVS_ACTION_GROUP) {
            uint32_t port_no;

            if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
                port_no = *XBUF_PAYLOAD(attr, uint32_t);
            } else {
                uint32_t group_id = *XBUF_PAYLOAD(attr, uint32_t);
                if (select_lag_port(pipeline, group_id, hash, &port_no) < 0) {
                    AIM_LOG_VERBOSE("LAG %u is empty", group_id);
                    continue;
                }
                AIM_LOG_VERBOSE("selected LAG %u port %u", group_id, port_no);
            }

            bool tagged;
            UNUSED bool out_global_vrf_allowed;
            UNUSED uint32_t out_vrf;
            if (check_vlan(pipeline, vlan_vid, port_no, &tagged, &out_vrf, &out_global_vrf_allowed) < 0) {
                AIM_LOG_VERBOSE("not flooding vlan %u to port %u", vlan_vid, port_no);
                continue;
            }

            if (port_no == in_port) {
                AIM_LOG_VERBOSE("not flooding vlan %u to ingress port %u", vlan_vid, port_no);
                continue;
            }

            uint16_t out_default_vlan_vid;
            uint32_t out_lag_id;
            bool out_disable_src_mac_check;
            if (lookup_port(pipeline, port_no, &out_default_vlan_vid, &out_lag_id, &out_disable_src_mac_check) < 0) {
                AIM_LOG_WARN("port %u not found during flood", port_no);
                continue;
            }

            if (out_lag_id != OF_GROUP_ANY && out_lag_id == lag_id) {
                AIM_LOG_VERBOSE("skipping ingress LAG %u", lag_id);
                continue;
            }

            uint16_t new_tag;
            if (tagged) {
                if (lookup_egr_vlan_xlate(pipeline, port_no, vlan_vid, &new_tag) < 0) {
                    new_tag = vlan_vid;
                }
            } else {
                new_tag = 0;
            }

            if (new_tag != tag) {
                if (new_tag == 0) {
                    pop_vlan(result);
                } else {
                    if (tag == 0) {
                        push_vlan(result, 0x8100);
                    }
                    set_vlan_vid(result, new_tag);
                }
                tag = new_tag;
            }

            output(result, port_no);
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_port(struct pipeline *pipeline, uint32_t port_no,
            uint16_t *default_vlan_vid, uint32_t *lag_id,
            bool *disable_src_mac_check)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    *default_vlan_vid = 0;
    *lag_id = OF_GROUP_ANY;
    *disable_src_mac_check = false;

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_PORT, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *default_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_LAG_ID) {
            *lag_id = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    *disable_src_mac_check = effects->disable_src_mac_check;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint32_t lag_id, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.lag_id = lag_id;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_VLAN_XLATE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
lookup_egr_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_EGR_VLAN_XLATE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
select_lag_port(struct pipeline *pipeline, uint32_t group_id, uint32_t hash, uint32_t *port_no)
{
    indigo_error_t rv;

    struct xbuf *actions;
    rv = ind_ovs_group_select(group_id, hash, &actions);
    if (rv < 0) {
        AIM_LOG_WARN("error selecting group %u bucket: %d", group_id, rv);
        return rv;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            *port_no = *XBUF_PAYLOAD(attr, uint32_t);
            return INDIGO_ERROR_NONE;
        }
    }

    AIM_LOG_WARN("no output action found in group %u bucket", group_id);
    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
lookup_my_station(struct pipeline *pipeline, const uint8_t *eth_addr)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    memcpy(&cfr.dl_dst, eth_addr, sizeof(cfr.dl_dst));

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_MY_STATION, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l3_route(struct pipeline *pipeline, uint32_t hash,
                uint32_t vrf, uint32_t ipv4_dst, bool global_vrf_allowed,
                of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                uint16_t *new_vlan_vid, uint32_t *lag_id)
{
    indigo_error_t ret;

    AIM_LOG_VERBOSE("looking up route for VRF=%u ip="FORMAT_IPV4" global_vrf_allowed=%u",
                    vrf, VALUE_IPV4((uint8_t *)&ipv4_dst), global_vrf_allowed);

    if ((ret = lookup_l3_host_route(
        pipeline, hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id)) == 0) {
        AIM_LOG_VERBOSE("hit in host route table");
        return INDIGO_ERROR_NONE;
    }

    if ((ret = lookup_l3_cidr_route(
        pipeline, hash, vrf, ipv4_dst,
        new_eth_src, new_eth_dst, new_vlan_vid, lag_id)) == 0) {
        AIM_LOG_VERBOSE("hit in CIDR route table");
        return INDIGO_ERROR_NONE;
    }

    if (global_vrf_allowed) {
        if ((ret = lookup_l3_host_route(
            pipeline, hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id)) == 0) {
            AIM_LOG_VERBOSE("hit in global host route table");
            return INDIGO_ERROR_NONE;
        }

        if ((ret = lookup_l3_cidr_route(
            pipeline, hash, 0, ipv4_dst,
            new_eth_src, new_eth_dst, new_vlan_vid, lag_id)) == 0) {
            AIM_LOG_VERBOSE("hit in global CIDR route table");
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_NOT_FOUND;
}

static indigo_error_t
lookup_l3_host_route(struct pipeline *pipeline, uint32_t hash,
                     uint32_t vrf, uint32_t ipv4_dst,
                     of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                     uint16_t *new_vlan_vid, uint32_t *lag_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_type = htons(0x0800);
    cfr.vrf = vrf;
    cfr.nw_dst = ipv4_dst;

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_L3_HOST_ROUTE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *lag_id = OF_GROUP_ANY;
    memset(new_eth_src, 0, sizeof(*new_eth_src));
    memset(new_eth_dst, 0, sizeof(*new_eth_dst));
    *new_vlan_vid = 0;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *lag_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l3_cidr_route(struct pipeline *pipeline, uint32_t hash,
                     uint32_t vrf, uint32_t ipv4_dst,
                     of_mac_addr_t *new_eth_src, of_mac_addr_t *new_eth_dst,
                     uint16_t *new_vlan_vid, uint32_t *lag_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_type = htons(0x0800);
    cfr.vrf = vrf;
    cfr.nw_dst = ipv4_dst;

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_L3_CIDR_ROUTE, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *lag_id = OF_GROUP_ANY;
    memset(new_eth_src, 0, sizeof(*new_eth_src));
    memset(new_eth_dst, 0, sizeof(*new_eth_dst));
    *new_vlan_vid = 0;

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->write_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_GROUP) {
            *lag_id = *XBUF_PAYLOAD(attr, uint32_t);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_SRC) {
            memcpy(new_eth_src->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_ETH_DST) {
            memcpy(new_eth_dst->addr, xbuf_payload(attr), OF_MAC_ADDR_BYTES);
        } else if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        }
    }

    return INDIGO_ERROR_NONE;
}
