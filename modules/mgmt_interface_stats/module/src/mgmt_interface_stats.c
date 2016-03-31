/* Copyright 2016, Big Switch Networks, Inc. */

#include <mgmt_interface_stats/mgmt_interface_stats.h>

#include <AIM/aim.h>
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>

#define AIM_LOG_MODULE_NAME mgmt_interface_stats
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

void
__mgmt_interface_stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}

static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);

void
mgmt_interface_stats_init(void)
{
    indigo_core_message_listener_register(message_listener);
}

static indigo_core_listener_result_t
handle_mgmt_interface_stats_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint32_t xid;
    of_str64_t stats_name;
    of_bsn_generic_stats_request_xid_get(msg, &xid);
    of_bsn_generic_stats_request_name_get(msg, &stats_name);

    if (strcmp(stats_name, "interface") && strcmp(stats_name, "mgmt_interface")) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_object_t *reply = of_bsn_generic_stats_reply_new(msg->version);
    of_bsn_generic_stats_reply_xid_set(reply, xid);

    indigo_cxn_send_controller_message(cxn_id, reply);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_GENERIC_STATS_REQUEST:
        return handle_mgmt_interface_stats_request(cxn_id, msg);
    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}
