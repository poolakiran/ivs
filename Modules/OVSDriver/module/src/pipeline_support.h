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

#ifndef OVSDRIVER_PIPELINE_SUPPORT_H
#define OVSDRIVER_PIPELINE_SUPPORT_H

#include "ovs_driver_int.h"
#include "actions.h"

#define UNUSED __attribute__((unused))

enum bsn_pktin_reason {
    BSN_PACKET_IN_REASON_NEW_HOST = 128,
    BSN_PACKET_IN_REASON_STATION_MOVE = 129,
    BSN_PACKET_IN_REASON_BAD_VLAN = 130,
    BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE = 131,
};

static void
pktin(struct ind_ovs_fwd_result *result, uint8_t reason)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_CONTROLLER,
                     &reason, sizeof(reason));
}

static void
output(struct ind_ovs_fwd_result *result, uint32_t port_no)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_OUTPUT,
                     &port_no, sizeof(port_no));
}

static void UNUSED
push_vlan(struct ind_ovs_fwd_result *result, uint16_t ethertype)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_PUSH_VLAN,
                     &ethertype, sizeof(ethertype));
}

static void UNUSED
pop_vlan(struct ind_ovs_fwd_result *result)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_POP_VLAN, NULL, 0);
}

static void UNUSED
set_vlan_vid(struct ind_ovs_fwd_result *result, uint16_t vlan_vid)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_SET_VLAN_VID,
                     &vlan_vid, sizeof(vlan_vid));
}

static void UNUSED
set_vlan_pcp(struct ind_ovs_fwd_result *result, uint8_t vlan_pcp)
{
    xbuf_append_attr(&result->actions, IND_OVS_ACTION_SET_VLAN_PCP,
                     &vlan_pcp, sizeof(vlan_pcp));
}

static struct ind_ovs_flow *
lookup(int table_id, const struct ind_ovs_cfr *cfr)
{
    struct ind_ovs_table *table = &ind_ovs_tables[table_id];

#ifndef NDEBUG
    LOG_VERBOSE("Looking up flow in table %d (%s)", table_id, table->name);
    ind_ovs_dump_cfr(cfr);
#endif

    struct flowtable_entry *fte = flowtable_match(table->ft, (const struct flowtable_key *)cfr);
    if (fte == NULL) {
        return NULL;
    }

    struct ind_ovs_flow *flow = container_of(fte, fte, struct ind_ovs_flow);
    return flow;
}

#endif
