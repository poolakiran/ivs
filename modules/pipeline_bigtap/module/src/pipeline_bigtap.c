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

#include <pipeline/pipeline.h>
#include <ivs/ivs.h>
#include <loci/loci.h>
#include <OVSDriver/ovsdriver.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <packet_trace/packet_trace.h>

#define AIM_LOG_MODULE_NAME pipeline_bigtap
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

/* Overall minimum average interval between packet-ins (in us) */
#define PKTIN_INTERVAL 3000

/* Overall packet-in burstiness tolerance. */
#define PKTIN_BURST_SIZE 32

struct ind_ovs_pktin_socket pktin_soc;

static void
pipeline_bigtap_init(const char *name)
{
    ind_ovs_pktin_socket_register(&pktin_soc, NULL, PKTIN_INTERVAL,
                                  PKTIN_BURST_SIZE);
}

static void
pipeline_bigtap_finish(void)
{
    ind_ovs_pktin_socket_unregister(&pktin_soc);
}

indigo_error_t
pipeline_bigtap_process(struct ind_ovs_parsed_key *key,
                        struct ind_ovs_parsed_key *mask,
                        struct xbuf *stats,
                        struct action_context *actx)
{
    uint64_t populated = mask->populated;
    memset(mask, 0xff, sizeof(*mask));
    mask->populated = populated;

    uint64_t userdata = IVS_PKTIN_USERDATA(OF_PACKET_IN_REASON_NO_MATCH, 0);
    uint32_t netlink_port = ind_ovs_pktin_socket_netlink_port(&pktin_soc);
    action_userspace(actx, &userdata, sizeof(uint64_t), netlink_port);

    return INDIGO_ERROR_NONE;
}

static struct pipeline_ops pipeline_bigtap_ops = {
    .init = pipeline_bigtap_init,
    .finish = pipeline_bigtap_finish,
    .process = pipeline_bigtap_process,
};

void
__pipeline_bigtap_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    pipeline_register("bigtap-full-match", &pipeline_bigtap_ops);
}
