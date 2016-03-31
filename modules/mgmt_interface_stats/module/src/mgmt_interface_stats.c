/* Copyright 2016, Big Switch Networks, Inc. */

#include <mgmt_interface_stats/mgmt_interface_stats.h>

#define AIM_LOG_MODULE_NAME mgmt_interface_stats
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(AIM_LOG_OPTIONS_DEFAULT, AIM_LOG_BITS_DEFAULT, NULL, 0);

void
__mgmt_interface_stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}
