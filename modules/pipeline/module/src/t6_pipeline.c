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

#define AIM_LOG_MODULE_NAME pipeline
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

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
};

static const bool flood_on_dlf = true;

static indigo_error_t lookup_l2(struct pipeline *pipeline, uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no);
static indigo_error_t check_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, bool *tagged);
static bool is_vlan_configured(struct pipeline *pipeline, uint16_t vlan_vid);
static indigo_error_t flood_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, struct pipeline_result *result);
static indigo_error_t lookup_port(struct pipeline *pipeline, uint32_t port_no, uint16_t *default_vlan_vid);
static indigo_error_t lookup_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate(struct pipeline *pipeline, uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);

indigo_error_t
t6_pipeline_process(struct pipeline *pipeline,
                    struct ind_ovs_cfr *cfr,
                    struct pipeline_result *result)
{
    uint16_t default_vlan_vid = 0;
    if (lookup_port(pipeline, cfr->in_port, &default_vlan_vid) < 0) {
        AIM_LOG_WARN("port %u not found", cfr->in_port);
        return INDIGO_ERROR_NONE;
    }

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
    uint32_t src_port_no = -1;
    if (lookup_l2(pipeline, vlan_vid, cfr->dl_src, &src_port_no) < 0) {
        AIM_LOG_VERBOSE("miss in source l2table lookup (new host)");
        pktin(result, BSN_PACKET_IN_REASON_NEW_HOST);
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in source l2table lookup, src_port_no=%u", src_port_no);

    if (src_port_no != cfr->in_port) {
        AIM_LOG_VERBOSE("incorrect port in source l2table lookup (station move)");
        pktin(result, BSN_PACKET_IN_REASON_STATION_MOVE);
        return INDIGO_ERROR_NONE;
    }

    /* Check for broadcast/multicast */
    if (cfr->dl_dst[0] & 1) {
        if (flood_vlan(pipeline, vlan_vid, cfr->in_port, result) < 0) {
            AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }
        return INDIGO_ERROR_NONE;
    }

    /* Destination lookup */
    uint32_t dst_port_no = -1;
    if (lookup_l2(pipeline, vlan_vid, cfr->dl_dst, &dst_port_no) < 0) {
        AIM_LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");
        if (flood_on_dlf) {
            if (flood_vlan(pipeline, vlan_vid, cfr->in_port, result) < 0) {
                AIM_LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
            }
        } else {
            pktin(result, BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE);
        }
        return INDIGO_ERROR_NONE;
    }

    AIM_LOG_VERBOSE("hit in destination l2table lookup, dst_port_no=%u", dst_port_no);

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
lookup_l2(struct pipeline *pipeline, uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

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
flood_vlan(struct pipeline *pipeline, uint16_t vlan_vid, uint32_t in_port, struct pipeline_result *result)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_VLAN, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    bool tagged = true;
    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            uint32_t port_no = *XBUF_PAYLOAD(attr, uint32_t);
            if (port_no != in_port) {
                uint16_t new_vlan_vid;
                if (tagged && lookup_egr_vlan_xlate(pipeline, port_no, vlan_vid, &new_vlan_vid) == 0) {
                    set_vlan_vid(result, new_vlan_vid);
                    output(result, port_no);
                    set_vlan_vid(result, vlan_vid);
                } else {
                    output(result, port_no);
                }
            }
        } else if (attr->nla_type == IND_OVS_ACTION_POP_VLAN) {
            pop_vlan(result);
            tagged = false;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_port(struct pipeline *pipeline, uint32_t port_no, uint16_t *default_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    struct ind_ovs_flow_effects *effects =
        pipeline->lookup(TABLE_ID_PORT, &cfr, NULL);
    if (effects == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&effects->apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *default_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
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