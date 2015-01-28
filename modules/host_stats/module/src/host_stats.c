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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <AIM/aim.h>
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <host_stats/host_stats.h>
#include "host_stats_log.h"

static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);

void
host_stats_init(void)
{
    indigo_core_message_listener_register(message_listener);
}

void
__host_stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}

static void
add_entry(of_object_t *entries, const char *name, const char *fmt, ...)
{
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

    va_list ap;
    char buf[1024];
    va_start(ap, fmt);
    int count = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (count < 0) {
        goto error;
    }

    {
        of_bsn_tlv_data_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)buf, .bytes=count };
        if (of_bsn_tlv_data_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    return;

error:
    AIM_LOG_WARN("Failed to append host stats entry '%s'", name);
}

static void
populate_host_stats_entries(of_object_t *entries)
{
    add_entry(entries, "test", "%d", 1234);
}

static indigo_core_listener_result_t
handle_host_stats_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint32_t xid;
    of_str64_t stats_name;
    of_bsn_generic_stats_request_xid_get(msg, &xid);
    of_bsn_generic_stats_request_name_get(msg, &stats_name);

    if (strcmp(stats_name, "host")) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_object_t *reply = of_bsn_generic_stats_reply_new(msg->version);
    of_bsn_generic_stats_reply_xid_set(reply, xid);
    of_object_t entries;
    of_bsn_generic_stats_reply_entries_bind(reply, &entries);

    populate_host_stats_entries(&entries);

    indigo_cxn_send_controller_message(cxn_id, reply);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_GENERIC_STATS_REQUEST:
        return handle_host_stats_request(cxn_id, msg);
    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}
