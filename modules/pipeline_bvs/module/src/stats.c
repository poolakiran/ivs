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

struct stats_handle pipeline_bvs_stats[PIPELINE_BVS_STATS_COUNT];

static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);

void
pipeline_bvs_stats_init(void)
{
    int i;
    for (i = 0; i < PIPELINE_BVS_STATS_COUNT; i++) {
        stats_alloc(&pipeline_bvs_stats[i]);
    }
    indigo_core_message_listener_register(message_listener);
}

void
pipeline_bvs_stats_finish(void)
{
    int i;
    for (i = 0; i < PIPELINE_BVS_STATS_COUNT; i++) {
        stats_free(&pipeline_bvs_stats[i]);
    }
    indigo_core_message_listener_unregister(message_listener);
}

static void
add_entry(of_object_t *entries, const char *name, int id)
{
    struct stats result;
    stats_get(&pipeline_bvs_stats[id], &result);

    of_bsn_generic_stats_entry_t entry;
    of_bsn_generic_stats_entry_init(&entry, entries->version, -1, 1);
    if (of_list_bsn_generic_stats_entry_append_bind(entries, &entry)) {
        goto error;
    }

    of_list_bsn_tlv_t tlvs;
    of_bsn_generic_stats_entry_tlvs_bind(&entry, &tlvs);
    of_bsn_tlv_t tlv;

    {
        of_bsn_tlv_name_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)name, .bytes=strlen(name) };
        if (of_bsn_tlv_name_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    {
        of_bsn_tlv_rx_packets_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_bsn_tlv_rx_packets_value_set(&tlv, result.packets);
    }

    return;

error:
    AIM_LOG_WARN("Failed to append pipeline_bvs stats entry '%s'", name);
}

static void
populate_stats_entries(of_object_t *entries)
{
#define stat(x) \
    add_entry(entries, #x, PIPELINE_BVS_STATS_ ## x);
    PIPELINE_STATS
#undef stat
}

static indigo_core_listener_result_t
handle_stats_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint32_t xid;
    of_str64_t stats_name;
    of_bsn_generic_stats_request_xid_get(msg, &xid);
    of_bsn_generic_stats_request_name_get(msg, &stats_name);

    if (strcmp(stats_name, "pipeline_bvs")) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_object_t *reply = of_bsn_generic_stats_reply_new(msg->version);
    of_bsn_generic_stats_reply_xid_set(reply, xid);
    of_object_t entries;
    of_bsn_generic_stats_reply_entries_bind(reply, &entries);

    populate_stats_entries(&entries);

    indigo_cxn_send_controller_message(cxn_id, reply);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_GENERIC_STATS_REQUEST:
        return handle_stats_request(cxn_id, msg);
    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}
