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

#include "pipeline_support.h"

enum table_id {
    TABLE_ID_L2 = 0,
    TABLE_ID_VLAN = 1,
    TABLE_ID_PORT = 2,
    TABLE_ID_VLAN_XLATE = 3,
    TABLE_ID_EGR_VLAN_XLATE = 4,
};

static const bool flood_on_dlf = true;

static indigo_error_t lookup_l2(uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no);
static indigo_error_t check_vlan(uint16_t vlan_vid, uint32_t in_port, bool *tagged);
static indigo_error_t flood_vlan(uint16_t vlan_vid, uint32_t in_port, struct ind_ovs_fwd_result *result);
static indigo_error_t lookup_port(uint32_t port_no, uint16_t *default_vlan_vid);
static indigo_error_t lookup_vlan_xlate(uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);
static indigo_error_t lookup_egr_vlan_xlate(uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid);

indigo_error_t
ind_ovs_pipeline_process(const struct ind_ovs_parsed_key *pkey,
                         struct ind_ovs_fwd_result *result)
{
    uint16_t default_vlan_vid = 0;
    if (lookup_port(pkey->in_port, &default_vlan_vid) < 0) {
        LOG_WARN("port %u not found", pkey->in_port);
        return INDIGO_ERROR_NONE;
    }

    uint16_t vlan_vid;
    if (ATTR_BITMAP_TEST(pkey->populated, OVS_KEY_ATTR_VLAN)) {
        vlan_vid = VLAN_VID(ntohs(pkey->vlan));
        uint16_t new_vlan_vid;
        if (lookup_vlan_xlate(pkey->in_port, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    } else {
        vlan_vid = default_vlan_vid;
        push_vlan(result, 0x8100);
        set_vlan_vid(result, vlan_vid);
    }

    UNUSED bool in_port_tagged;
    if (check_vlan(vlan_vid, pkey->in_port, &in_port_tagged) < 0) {
        LOG_VERBOSE("port %u not allowed on vlan %u (bad VLAN)", pkey->in_port, vlan_vid);
        pktin(result, BSN_PACKET_IN_REASON_BAD_VLAN);
        return INDIGO_ERROR_NONE;
    }

    /* Source lookup */
    uint32_t src_port_no = -1;
    if (lookup_l2(vlan_vid, pkey->ethernet.eth_src, &src_port_no) < 0) {
        LOG_VERBOSE("miss in source l2table lookup (new host)");
        pktin(result, BSN_PACKET_IN_REASON_NEW_HOST);
        return INDIGO_ERROR_NONE;
    }

    LOG_VERBOSE("hit in source l2table lookup, src_port_no=%u", src_port_no);

    if (src_port_no != pkey->in_port) {
        LOG_VERBOSE("incorrect port in source l2table lookup (station move)");
        pktin(result, BSN_PACKET_IN_REASON_STATION_MOVE);
        return INDIGO_ERROR_NONE;
    }

    /* Check for broadcast/multicast */
    if (pkey->ethernet.eth_dst[0] & 1) {
        if (flood_vlan(vlan_vid, pkey->in_port, result) < 0) {
            LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
        }
        return INDIGO_ERROR_NONE;
    }

    /* Destination lookup */
    uint32_t dst_port_no = -1;
    if (lookup_l2(vlan_vid, pkey->ethernet.eth_dst, &dst_port_no) < 0) {
        LOG_VERBOSE("miss in destination l2table lookup (destination lookup failure)");
        if (flood_on_dlf) {
            if (flood_vlan(vlan_vid, pkey->in_port, result) < 0) {
                LOG_WARN("missing VLAN entry for vlan %u", vlan_vid);
            }
        } else {
            pktin(result, BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE);
        }
        return INDIGO_ERROR_NONE;
    }

    LOG_VERBOSE("hit in destination l2table lookup, dst_port_no=%u", dst_port_no);

    bool out_port_tagged;
    if (check_vlan(vlan_vid, dst_port_no, &out_port_tagged) < 0) {
        LOG_WARN("output port %u not allowed on vlan %u", dst_port_no, vlan_vid);
        return INDIGO_ERROR_NONE;
    }

    if (!out_port_tagged) {
        pop_vlan(result);
    } else {
        uint16_t new_vlan_vid;
        if (lookup_egr_vlan_xlate(dst_port_no, vlan_vid, &new_vlan_vid) == 0) {
            vlan_vid = new_vlan_vid;
            set_vlan_vid(result, vlan_vid);
        }
    }

    output(result, dst_port_no);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_l2(uint16_t vlan_vid, const uint8_t *eth_addr, uint32_t *port_no)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);
    memcpy(&cfr.dl_dst, eth_addr, sizeof(cfr.dl_dst));

    struct ind_ovs_flow *flow = lookup(TABLE_ID_L2, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            *port_no = *XBUF_PAYLOAD(attr, uint32_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
check_vlan(uint16_t vlan_vid, uint32_t in_port, bool *tagged)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow *flow = lookup(TABLE_ID_VLAN, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *tagged = true;

    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
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
flood_vlan(uint16_t vlan_vid, uint32_t in_port, struct ind_ovs_fwd_result *result)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow *flow = lookup(TABLE_ID_VLAN, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    bool tagged = true;
    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_OUTPUT) {
            uint32_t port_no = *XBUF_PAYLOAD(attr, uint32_t);
            if (port_no != in_port) {
                uint16_t new_vlan_vid;
                if (tagged && lookup_egr_vlan_xlate(port_no, vlan_vid, &new_vlan_vid) == 0) {
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
lookup_port(uint32_t port_no, uint16_t *default_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;

    struct ind_ovs_flow *flow = lookup(TABLE_ID_PORT, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *default_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lookup_vlan_xlate(uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow *flow = lookup(TABLE_ID_VLAN_XLATE, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}

static indigo_error_t
lookup_egr_vlan_xlate(uint32_t port_no, uint16_t vlan_vid, uint16_t *new_vlan_vid)
{
    struct ind_ovs_cfr cfr;
    memset(&cfr, 0, sizeof(cfr));

    cfr.in_port = port_no;
    cfr.dl_vlan = htons(VLAN_TCI(vlan_vid, 0) | VLAN_CFI_BIT);

    struct ind_ovs_flow *flow = lookup(TABLE_ID_EGR_VLAN_XLATE, &cfr);
    if (flow == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nlattr *attr;
    XBUF_FOREACH2(&flow->effects.apply_actions, attr) {
        if (attr->nla_type == IND_OVS_ACTION_SET_VLAN_VID) {
            *new_vlan_vid = *XBUF_PAYLOAD(attr, uint16_t);
            return INDIGO_ERROR_NONE;
        }
    }

    return INDIGO_ERROR_PARAM;
}
