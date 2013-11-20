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
    TABLE_ID_FLOOD = 11,
};

static const bool flood_on_dlf = true;

static indigo_error_t lookup_l2(struct pipeline *pipeline, uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no, uint32_t *group_id);
static indigo_error_t check_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, bool *tagged);
static bool is_vlan_configured(struct pipeline *pipeline, uint16_t vlan_vid);
static indigo_error_t flood_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, uint32_t lag_id, uint32_t hash, struct pipeline_result *result);
static indigo_error_t lookup_port(struct pipeline *pipeline, uint32_t port_no, uint16_t *default_vlan_vid, uint32_t *lag_id);
static indigo_error_t lookup_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t select_lag_port(struct pipeline *pipeline, uint32_t group_id, uint32_t hash, uint32_t *port_no);

indigo_error_t
t6_pipeline_process(struct pipeline *pipeline,
                    struct ind_ovs_cfr *cfr,
                    struct pipeline_result *result)
{
    uint32_t hash = murmur_hash(cfr, sizeof(*cfr), 0);

    if (cfr->dl_type == htons(0x88cc)) {
        AIM_LOG_VERBOSE("sending ethertype %#x directly to controller", ntohs(cfr->dl_type));
        pktin(result, OF_PACKET_IN_REASON_ACTION);
        return INDIGO_ERROR_NONE;
    }

    uint16_t default_vlan_vid;
    uint32_t lag_id;
    if (lookup_port(pipeline, cfr->in_port, &default_vlan_vid, &lag_id) < 0) {
        AIM_LOG_WARN("port %u not found", cfr->in_port);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in port table lookup, default_vlan_vid=%u lag_id=%u", default_vlan_vid, lag_id);

    uint16_t vlan_vid;
    if (cfr->dl_vlan & htons(VLAN_CFI_BIT)) {
        vlan_vid = VLAN_VID(ntohs(cfr->dl_vlan));
        uint16_t new_vlan_vid;
        if (lookup_vlan_xlate(pipeline, cfr->in_port, vlan_vid, &new_vlan_vid) == 0) {
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
    if (check_vlan(pipeline, vlan_vid, cfr->in_port, &in_port_tagged) < 0) {
        AIM_LOG_VERBOSE("port %u not allowed on vlan %u", cfr->in_port, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

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

    /* Check for broadcast/multicast */
    if (cfr->dl_dst[0] & 1) {
        if (flood_vlan(pipeline, vlan_vid, cfr->in_port, lag_id, hash, result) < 0) {
            AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }
        return INDIGO_ERROR_NONE;
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
    if (check_vlan(pipeline, vlan_vid, dst_port_no, &out_port_tagged) < 0) {
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
check_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, bool *tagged)
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

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            uint32_t port_no = *XBUF_PAYLOAD(attr, uint32_t);
            if (port_no == in_port) {
                return INDIGO_ERROR_NONE;
            }
        } else if (attr->nla_type == IND_OVS_ACTION_POP_VLAN) {
            *tagged = false;
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
            if (check_vlan(pipeline, vlan_vid, port_no, &tagged) < 0) {
                AIM_LOG_VERBOSE("not flooding vlan %u to port %u", vlan_vid, port_no);
                continue;
            }

            /* TODO also check lag_id */
            if (port_no == in_port) {
                AIM_LOG_VERBOSE("not flooding vlan %u to ingress port %u", vlan_vid, port_no);
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
            uint16_t *default_vlan_vid, uint32_t *lag_id)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    *default_vlan_vid = 0;
    *lag_id = OF_GROUP_ANY;

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

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
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
