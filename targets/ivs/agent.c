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
#include <version_stats/version_stats.h>
#include <cdpa/cdpa.h>
#include <inband/inband.h>
#include <SocketManager/socketmanager.h>
#include <igmpa/igmpa.h>
#include <mgmt_interface_stats/mgmt_interface_stats.h>

static void
lldp_timer(void *cookie)
{
    of_port_no_t port_no = ind_ovs_uplink_select();
    if (port_no != OF_PORT_DEST_NONE) {
        inband_send_lldp(port_no);
    }
}

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
    version_stats_init();
    mgmt_interface_stats_init();

    if (cdpa_init() < 0) {
        AIM_DIE("Failed to initialize CDP Agent module");
    }

    ind_soc_timer_event_register(lldp_timer, NULL, 10000);

    if (igmpa_init() < 0) {
        AIM_DIE("Failed to initialize IGMP Agent module");
    }
}
