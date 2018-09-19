/****************************************************************
 *
 *        Copyright 2017, Big Switch Networks, Inc.
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

#include <OVSDriver/ovsdriver_config.h>
#include "ovs_driver_int.h"

#if OVSDRIVER_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
ovsdriver_ucli_ucli__upcall__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc, "upcall", 0,
                      "$summary#Print upcall thread information.");

    ind_ovs_upcall_thread_info_print(uc);
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__port__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc, "port", -1,
                      "$summary#Print given/all port details.");

    if (uc->pargs->count == 0) {
        ind_ovs_port_info_print(uc, OF_PORT_DEST_NONE);
    } else if (uc->pargs->count == 1) {
        of_port_no_t of_port;

        UCLI_ARGPARSE_OR_RETURN(uc, "i", &of_port);
        ind_ovs_port_info_print(uc, of_port);
    }
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__port_nl_reset__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc, "port_nl_reset", -1,
                      "$summary# Reinitialize netlink socket for given/all ports.");

    if (uc->pargs->count == 0) {
        /* Reset netlink socket of all ports */
        ind_ovs_port_nl_socket_reset(uc, OF_PORT_DEST_NONE);
    } else if (uc->pargs->count == 1) {
        of_port_no_t of_port;

        UCLI_ARGPARSE_OR_RETURN(uc, "i", &of_port);
        ind_ovs_port_nl_socket_reset(uc, of_port);
    }
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__port_nl_reset_params__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc, "port_nl_reset_params", -1,
                      "$summary# Configure monitor_interval and drop_tolerance"
                      "$args#[monitor_interval] [drop_tolerance]");

    if (uc->pargs->count == 2) {
        int interval, tolerance;
        UCLI_ARGPARSE_OR_RETURN(uc, "ii", &interval, &tolerance);
        ind_ovs_port_nl_socket_reset_params(uc, interval, tolerance);
    } else {
        ucli_printf(uc, "Usage: port_nl_reset_params "
                    "<monitor_interval> <drop_tolerance>\n");
        ucli_printf(uc, "<monitor_interval> Periodic timer(in secs) to check drops\n");
        ucli_printf(uc, "<drop_tolerance> Number of cosecutive drop iterations to reset nl socket\n");
        ind_ovs_port_nl_socket_reset_params(uc, -1, -1);
    }
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__kflow__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc, "kflow", -1,
                      "$summary#Print kflows on given/all ports.");

    if (uc->pargs->count == 0) {
        ind_ovs_kflow_print(uc, OF_PORT_DEST_NONE);
    } else if (uc->pargs->count == 1) {
        of_port_no_t of_port;

        UCLI_ARGPARSE_OR_RETURN(uc, "i", &of_port);
        ind_ovs_kflow_print(uc, of_port);
    }
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__kflow_trace__(ucli_context_t* uc)
{
    int choice = 2;

    UCLI_COMMAND_INFO(uc, "kflow-trace", -1,
                      "$summary#Log kflow traces for given/all ports."
                      "$args#[on|off|status] [of-port]");

    if (uc->pargs->count == 0) {
        ind_ovs_kflow_trace(uc, choice, OF_PORT_DEST_NONE);
    } else if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "{choice}",
                                &choice, "option", 3, "off", "on", "status");
        ind_ovs_kflow_trace(uc, choice, OF_PORT_DEST_NONE);
    } else if (uc->pargs->count == 2) {
        of_port_no_t of_port;

        UCLI_ARGPARSE_OR_RETURN(uc, "{choice}i",
                                &choice, "option", 3, "off", "on", "status", &of_port);
        ind_ovs_kflow_trace(uc, choice, of_port);
    } else {
        ucli_printf(uc, " Usage: kflow-trace [on [of_port]|off|status]\n");
    }
    return UCLI_STATUS_OK;
}

static ucli_status_t
ovsdriver_ucli_ucli__kflow_trace_params__(ucli_context_t* uc)
{
    uint32_t size = 0, count = 0;

    UCLI_COMMAND_INFO(uc, "kflow-trace-params", -1,
                      "$summary#Configure kflow trace log file size and count."
                      "$args#[<size> <count>]");

    if (uc->pargs->count == 0) {
        ind_ovs_kflow_trace_params(uc, false, size, count);
        return UCLI_STATUS_OK;
    } else if (uc->pargs->count == 2) {
        UCLI_ARGPARSE_OR_RETURN(uc, "ii", &size, &count);

        if (size >= 5 && size <= 50 &&
            count >= 1 && count <= 9) {
            ind_ovs_kflow_trace_params(uc, true, size*MEGA_BYTE, count);
            return UCLI_STATUS_OK;
        }
    }

    ucli_printf(uc, " Usage: kflow-trace-params [<size-in-mb> <count>]\n");
    ucli_printf(uc, "        <size> range 5 MBytes to 50 MBytes\n");
    ucli_printf(uc, "        <count> range 1 to 9\n");
    return UCLI_STATUS_OK;
}

/* <auto.ucli.handlers.start> */
/******************************************************************************
 *
 * These handler table(s) were autogenerated from the symbols in this
 * source file.
 *
 *****************************************************************************/
static ucli_command_handler_f ovsdriver_ucli_ucli_handlers__[] =
{
    ovsdriver_ucli_ucli__upcall__,
    ovsdriver_ucli_ucli__port__,
    ovsdriver_ucli_ucli__port_nl_reset__,
    ovsdriver_ucli_ucli__port_nl_reset_params__,
    ovsdriver_ucli_ucli__kflow__,
    ovsdriver_ucli_ucli__kflow_trace__,
    ovsdriver_ucli_ucli__kflow_trace_params__,
    NULL
};
/******************************************************************************/
/* <auto.ucli.handlers.end> */

static ucli_module_t
ovsdriver_ucli_module__ =
    {
        "ovsdriver_ucli",
        NULL,
        ovsdriver_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
ovsdriver_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&ovsdriver_ucli_module__);
    n = ucli_node_create("ovsdriver", NULL, &ovsdriver_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("ovsdriver"));
    return n;
}

#else
void*
ovsdriver_ucli_node_create(void)
{
    return NULL;
}
#endif