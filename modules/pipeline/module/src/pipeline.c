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

#include <pipeline/pipeline.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ivs/ivs.h>
#include <loci/loci.h>
#include <packet_trace/packet_trace.h>
#include <inband/inband.h>

#define AIM_LOG_MODULE_NAME pipeline
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define MAX_PIPELINES 16

struct pipeline {
    const char *name;
    const struct pipeline_ops *ops;
};

static struct pipeline pipelines[MAX_PIPELINES];

static struct pipeline *current_pipeline;

static int queue_priority_inband = -1;

static struct ind_ovs_pktin_socket inband_pktin_soc;

void
pipeline_register(const char *name, const struct pipeline_ops *ops)
{
    int i;
    for (i = 0; i < MAX_PIPELINES; i++) {
        struct pipeline *p = &pipelines[i];
        if (p->name == NULL) {
            p->name = aim_strdup(name);
            p->ops = ops;
            return;
        } else if (!strcmp(p->name, name)) {
            AIM_DIE("attempted to register duplicate pipeline '%s'", name);
        }
    }

    AIM_DIE("attempted to register more than %d pipelines", MAX_PIPELINES);
}

indigo_error_t
pipeline_set(const char *name)
{
    struct pipeline *new_pipeline = NULL;

    if (name != NULL) {
        int i;
        for (i = 0; i < MAX_PIPELINES; i++) {
            struct pipeline *p = &pipelines[i];
            if (p->name != NULL && !strcmp(p->name, name)) {
                new_pipeline = p;
            }
        }

        if (new_pipeline == NULL) {
            return INDIGO_ERROR_NOT_FOUND;
        }
    }

    if (new_pipeline == current_pipeline) {
        return INDIGO_ERROR_NONE;
    }

    if (current_pipeline != NULL) {
        current_pipeline->ops->finish();
        current_pipeline = NULL;
    }

    if (name == NULL) {
        return INDIGO_ERROR_NONE;
    }

    new_pipeline->ops->init(name);
    current_pipeline = new_pipeline;
    return INDIGO_ERROR_NONE;
}

const char *
pipeline_get(void)
{
    AIM_TRUE_OR_DIE(current_pipeline != NULL);
    return current_pipeline->name;
}

void
pipeline_list(of_desc_str_t **ret_pipelines, int *num_pipelines)
{
    *ret_pipelines = aim_zmalloc(sizeof(of_desc_str_t) * MAX_PIPELINES);

    int i, j = 0;
    for (i = 0; i < MAX_PIPELINES; i++) {
        if (pipelines[i].name != 0) {
            strncpy((*ret_pipelines)[j++], pipelines[i].name, sizeof(of_desc_str_t));
        }
    }

    *num_pipelines = j;
}

indigo_error_t
pipeline_process(struct ind_ovs_parsed_key *key,
                 struct ind_ovs_parsed_key *mask,
                 struct xbuf *stats,
                 struct action_context *actx)
{
    AIM_TRUE_OR_DIE(current_pipeline != NULL);

    mask->in_port = -1;
    packet_trace_begin(key->in_port);

    mask->populated = key->populated;
    ATTR_BITMAP_SET(mask->populated, OVS_KEY_ATTR_ETHERTYPE);

    if (ind_ovs_inband_vlan != VLAN_INVALID) {
        if (ind_ovs_uplink_check(key->in_port)) {
            mask->ethertype = -1;
            if (key->ethertype == htons(0x88cc)) {
                uint64_t userdata = 0;
                uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&inband_pktin_soc);
                action_userspace(actx, &userdata, sizeof(uint64_t), netlink_port);
            }

            mask->vlan = -1;
            if (VLAN_VID(ntohs(key->vlan)) == ind_ovs_inband_vlan) {
                packet_trace("Sending in-band management packet from uplink to internal port");
                action_pop_vlan(actx);
                action_output(actx, IVS_INBAND_PORT);
                packet_trace_end();
                return INDIGO_ERROR_NONE;
            }
            /* fall through */
        } else if (key->in_port == IVS_INBAND_PORT) {
            packet_trace("Sending in-band management packet from internal port to uplink");
            uint32_t port = ind_ovs_uplink_select();
            if (port != OF_PORT_DEST_NONE) {
                action_push_vlan(actx);
                action_set_vlan_vid(actx, ind_ovs_inband_vlan);
                if (queue_priority_inband != -1) {
                    action_set_priority(actx, queue_priority_inband);
                }
                action_output(actx, port);
            } else {
                packet_trace("No available uplink");
            }
            packet_trace_end();
            return INDIGO_ERROR_NONE;
        }
        /* fall through */
    }

    indigo_error_t rv = current_pipeline->ops->process(key, mask, stats, actx);
    packet_trace_end();
    return rv;
}

void
pipeline_inband_queue_priority_set(int priority)
{
    queue_priority_inband = priority;
}

static void
process_inband_pktin(uint8_t *data, unsigned int len,
                     uint8_t reason, uint64_t metadata,
                     struct ind_ovs_parsed_key *pkey)
{
    inband_receive_packet(data, len, pkey->in_port);
}

void
pipeline_init(void)
{
    ind_ovs_pktin_socket_register(&inband_pktin_soc, process_inband_pktin, 5000, 32);
}

void
__pipeline_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
