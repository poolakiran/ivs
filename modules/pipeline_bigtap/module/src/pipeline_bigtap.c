/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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
#include <ivs/actions.h>
#include <loci/loci.h>

#define AIM_LOG_MODULE_NAME pipeline_bigtap
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

#define TABLE_ID 1
#define ETH_P_LLDP 0x88cc

static void
pipeline_bigtap_init(const char *name)
{
}

static void
pipeline_bigtap_finish(void)
{
}

indigo_error_t
pipeline_bigtap_process(struct ind_ovs_cfr *cfr,
                          struct pipeline_result *result)
{
    if (cfr->dl_type == ETH_P_LLDP) {
        /* Send LLDPs to controller */
        uint8_t reason = OF_PACKET_IN_REASON_ACTION;
        xbuf_append_attr(&result->actions, IND_OVS_ACTION_CONTROLLER,
                         &reason, sizeof(reason));
        return INDIGO_ERROR_NONE;
    }


    struct ind_ovs_flow_effects *effects =
        ind_ovs_fwd_pipeline_lookup(TABLE_ID, cfr, &result->stats);
    if (effects == NULL) {
        /* Drop packets that miss in the table */
        return INDIGO_ERROR_NONE;
    }

    xbuf_append(&result->actions, xbuf_data(&effects->apply_actions),
                xbuf_length(&effects->apply_actions));

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
    pipeline_register("bigtap-full-match", &pipeline_bigtap_ops);
}
