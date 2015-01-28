#include <lacpa/lacpa.h>
#include <lldpa/lldpa.h>
#include <arpa/arpa.h>
#include <router_ip_table/router_ip_table.h>
#include <icmpa/icmpa.h>
#include <pipeline/pipeline.h>
#include <dhcpra/dhcpra.h>
#include <nat/nat.h>
#include <sflowa/sflowa.h>
#include <host_stats/host_stats.h>

void
ivs_agent_init(void)
{
    if (lacpa_init() < 0) {
        AIM_DIE("Failed to initialize LACP Agent module");
    }

    if (lldpa_system_init() < 0) {
        AIM_DIE("Failed to initialize LLDP Agent module");
    }

    if (arpa_init() < 0) {
        AIM_DIE("Failed to initialize ARP Agent module");
    }

    if (router_ip_table_init() < 0) {
        AIM_DIE("Failed to initialize Router IP table module");
    }

    if (icmpa_init() < 0) {
        AIM_DIE("Failed to initialize ICMP Agent module");
    }

    if (dhcpra_system_init() < 0) {
        AIM_DIE("Failed to initialize DHCP relay table and agent module");
    }

    nat_init();

    if (sflowa_init() < 0) {
        AIM_DIE("Failed to initialize SFLOW agent module");
    }

    host_stats_init();
}
