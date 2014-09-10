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

/******************************************************************************
 *
 *  Indigo Virtual Switch.
 *
 *  This switch uses the OVSDriver module to provide the Forwarding and
 *  PortManager interfaces.
 *
 *
 *****************************************************************************/
#include <unistd.h>
#include <AIM/aim.h>
#include <AIM/aim_pvs_syslog.h>
#include <BigList/biglist.h>
#include <indigo/port_manager.h>
#include <SocketManager/socketmanager.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <OFStateManager/ofstatemanager.h>
#include <Configuration/configuration.h>
#include <OVSDriver/ovsdriver.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <stdbool.h>
#include <linux/un.h>
#include <pipeline/pipeline.h>
#include <malloc.h>
#include <inband/inband.h>

#define AIM_LOG_MODULE_NAME ivs
#include <AIM/aim_log.h>

AIM_LOG_STRUCT_DEFINE(
                      AIM_LOG_OPTIONS_DEFAULT,
                      AIM_LOG_BITS_DEFAULT,
                      NULL,     /* Custom Log Map */
                      0
                      );

#ifndef BUILD_ID
#define BUILD_ID devel
#endif

void ivs_cli_init(const char *path);

static int
ivs_loci_logger(loci_log_level_t level,
                const char *fname, const char *file, int line,
                const char *format, ...);

static const char *program_version = "ivs 0.5";

static ind_soc_config_t soc_cfg;
static ind_cxn_config_t cxn_cfg;
static ind_core_config_t core_cfg;

static int sighup_eventfd;
static int sigterm_eventfd;

/* Command line options */

static enum loglevel {
    LOGLEVEL_DEFAULT,
    LOGLEVEL_VERBOSE,
    LOGLEVEL_TRACE
} loglevel = LOGLEVEL_DEFAULT;

static biglist_t *controllers = NULL;
static biglist_t *listeners = NULL;
static biglist_t *interfaces = NULL;
static biglist_t *uplinks = NULL;
static uint64_t dpid = 0;
static int use_syslog = 0;
static char *datapath_name = "ivs";
static char *config_filename = NULL;
static char *openflow_version = NULL;
static char *pipeline = NULL;

static int
parse_controller(const char *str,
                 indigo_cxn_protocol_params_t *_proto,
                 int default_port)
{
    char buf[128];
    char *strtok_state = NULL;
    char *ip, *port_str;
    indigo_cxn_params_tcp_over_ipv4_t *proto = &_proto->tcp_over_ipv4;
    struct sockaddr_in sa;

    strncpy(buf, str, sizeof(buf));
    strtok_state = buf;

    proto->protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV4;

    ip = strtok_r(NULL, ":/", &strtok_state);
    if (ip == NULL) {
        AIM_LOG_ERROR("Controller spec \"%s\" missing IP address", str);
        return -1;
    } else if (inet_pton(AF_INET, ip, &sa) != 1) {
        AIM_LOG_ERROR("Could not parse IP address \"%s\"", ip);
        return -1;
    } else {
        strncpy(proto->controller_ip, ip, sizeof(proto->controller_ip));
    }

    port_str = strtok_r(NULL, ":/", &strtok_state);
    if (port_str == NULL) {
        proto->controller_port = default_port;
    } else {
        char *endptr;
        long port = strtol(port_str, &endptr, 0);
        if (*port_str == '\0' || *endptr != '\0') {
            AIM_LOG_ERROR("Could not parse port \"%s\"", port_str);
            return -1;
        } else if (port <= 0 || port > 65535) {
            AIM_LOG_ERROR("Invalid port \"%s\"", port_str);
            return -1;
        } else {
            proto->controller_port = atoi(port_str);
        }
    }

    return 0;
}

static void
parse_options(int argc, char **argv)
{
    while (1) {
        int option_index = 0;

        /* Options without short equivalents */
        enum long_opts {
            OPT_START = 256,
            OPT_NAME,
            OPT_DPID,
            OPT_SYSLOG,
            OPT_VERSION,
            OPT_MAX_FLOWS,
            OPT_PIPELINE,
            OPT_INBAND_VLAN,
        };

        static struct option long_options[] = {
            {"verbose",     no_argument,       0,  'v' },
            {"trace",       no_argument,       0,  't' },
            {"interface",   required_argument, 0,  'i' },
            {"controller",  required_argument, 0,  'c' },
            {"listen",      required_argument, 0,  'l' },
            {"pipeline",    optional_argument, 0,  OPT_PIPELINE },
            {"dpid",        required_argument, 0,  OPT_DPID },
            {"syslog",      no_argument,       0,  OPT_SYSLOG },
            {"uplink",      required_argument, 0,  'u' },
            {"inband-vlan", required_argument, 0,  OPT_INBAND_VLAN },
            {"help",        no_argument,       0,  'h' },
            {"version",     no_argument,       0,  OPT_VERSION },
            /* Undocumented options */
            {"name",        required_argument, 0,  OPT_NAME },
            {"max-flows",   required_argument, 0,  OPT_MAX_FLOWS },
            {"config-file", required_argument, 0,  'f' },
            {"openflow-version", required_argument, 0, 'V' },
            {0,             0,                 0,  0 }
        };

        int c = getopt_long(argc, argv, "vtl:i:u:c:f:hV:",
                            long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'v':
            loglevel = LOGLEVEL_VERBOSE;
            break;

        case 't':
            loglevel = LOGLEVEL_TRACE;
            break;

        case 'c':
            controllers = biglist_append(controllers, optarg);
            break;

        case 'l':
            listeners = biglist_append(listeners, optarg);
            break;

        case 'i':
            interfaces = biglist_append(interfaces, optarg);
            break;

        case 'u':
            uplinks = biglist_append(uplinks, optarg);
            break;

        case 'f':
            config_filename = optarg;
            break;

        case 'V':
            openflow_version = optarg;
            break;

        case OPT_NAME:
            datapath_name = strdup(optarg);
            break;

        case OPT_DPID:
            AIM_ASSERT(optarg != NULL, "clang-analyzer workaround");
            dpid = strtoll(optarg, NULL, 16);
            break;

        case OPT_SYSLOG:
            use_syslog = 1;
            break;

        case OPT_VERSION:
            printf("%s (%s)\n", program_version, AIM_STRINGIFY(BUILD_ID));
            exit(0);
            break;

        case OPT_MAX_FLOWS:
            /* Ignored for compatibility */
            break;

        case OPT_PIPELINE:
            pipeline = optarg ? optarg : "experimental";
            break;

        case OPT_INBAND_VLAN:
            ind_ovs_inband_vlan = atoi(optarg);
            break;

        case 'h':
        case '?':
            printf("ivs: Indigo Virtual Switch\n");
            printf("Usage: ivs [OPTION]...\n");
            printf("\n");
            printf("  -v, --verbose               Verbose logging\n");
            printf("  -t, --trace                 Very verbose logging\n");
            printf("  -c, --controller=IP:PORT    Connect to a controller at startup\n");
            printf("  -l, --listen=IP:PORT        Listen for dpctl connections\n");
            printf("  -i, --interface=INTERFACE   Attach a network interface at startup\n");
            printf("  --pipeline=NAME             Set the default forwarding pipeline (standard-1.0 or standard-1.3)\n");
            //printf("  -f, --config-file=FILE      Read a configuration file\n");
            //printf("  --name=NAME                 Set the name of the kernel datapath (default ivs)\n");
            printf("  --dpid=DPID                 Set datapath ID (default autogenerated)\n");
            printf("  --syslog                    Log to syslog instead of stderr\n");
            printf("  --inband-vlan=VLAN          Enable in-band management on the specified VLAN\n");
            printf("  -h,--help                   Display this help message and exit\n");
            printf("  --version                   Display version information and exit\n");
            exit(c == 'h' ? 0 : 1);
            break;
        }
    }
}

static void
sighup_callback(int socket_id, void *cookie,
                int read_ready, int write_ready, int error_seen)
{
    uint64_t x;
    if (read(sighup_eventfd, &x, sizeof(x)) < 0) {
        /* silence warn_unused_result */
    }
    AIM_LOG_MSG("Received SIGHUP");

    if (config_filename) {
        ind_cfg_load();
    }
}

static void
sighup(int signum)
{
    uint64_t x = 1;
    if (write(sighup_eventfd, &x, sizeof(x)) < 0) {
        /* silence warn_unused_result */
    }
}

static void
sigterm_callback(int socket_id, void *cookie,
                 int read_ready, int write_ready, int error_seen)
{
    uint64_t x;
    if (read(sigterm_eventfd, &x, sizeof(x)) < 0) {
        /* silence warn_unused_result */
    }

    ind_soc_run_status_set(IND_SOC_RUN_STATUS_EXIT);
}

static void
sigterm(int signum)
{
    uint64_t x = 1;
    if (write(sigterm_eventfd, &x, sizeof(x)) < 0) {
        /* silence warn_unused_result */
    }
}

int
aim_main(int argc, char* argv[])
{
    AIM_LOG_STRUCT_REGISTER();

    /*
     * We queue many (up to 20) 64KB messages before sending them on the socket
     * with a single writev(). After we free all the messages the malloc
     * implementation would see we have more than 128KB (the default trim value)
     * free and return it to the OS with a call to brk(). Every time we
     * allocate a new message we have to get the memory with brk() all over
     * again.
     *
     * Increasing the trim threshold above the size of our working set
     * eliminates this churn.
     */
    mallopt(M_TRIM_THRESHOLD, 2*1024*1024);

    loci_logger = ivs_loci_logger;

    core_cfg.expire_flows = 1;
    core_cfg.stats_check_ms = 900;
    core_cfg.disconnected_mode = INDIGO_CORE_DISCONNECTED_MODE_STICKY;

    parse_options(argc, argv);

    /* Setup logging from command line options */

    if (loglevel >= LOGLEVEL_DEFAULT) {
        aim_log_fid_set_all(AIM_LOG_FLAG_MSG, 1);
        aim_log_fid_set_all(AIM_LOG_FLAG_FATAL, 1);
        aim_log_fid_set_all(AIM_LOG_FLAG_ERROR, 1);
        aim_log_fid_set_all(AIM_LOG_FLAG_WARN, 1);
    }

    if (loglevel >= LOGLEVEL_VERBOSE) {
        aim_log_fid_set_all(AIM_LOG_FLAG_VERBOSE, 1);
    }

    if (loglevel >= LOGLEVEL_TRACE) {
        aim_log_fid_set_all(AIM_LOG_FLAG_TRACE, 1);
    }

    if (use_syslog) {
        aim_log_pvs_set_all(aim_pvs_syslog_open("ivs", LOG_NDELAY, LOG_DAEMON));
    }

    AIM_LOG_MSG("Starting %s (%s) pid %d", program_version, AIM_STRINGIFY(BUILD_ID), getpid());

    /* Initialize all modules */

    if (ind_soc_init(&soc_cfg) < 0) {
        AIM_LOG_FATAL("Failed to initialize Indigo socket manager");
        return 1;
    }

    if (ind_cxn_init(&cxn_cfg) < 0) {
        AIM_LOG_FATAL("Failed to initialize Indigo connection manager");
        return 1;
    }

    if (ind_core_init(&core_cfg) < 0) {
        AIM_LOG_FATAL("Failed to initialize Indigo core module");
        return 1;
    }

    if (ind_ovs_init(datapath_name) < 0) {
        AIM_LOG_FATAL("Failed to initialize OVSDriver module");
        return 1;
    }

    inband_init();

    if (pipeline == NULL) {
        if (openflow_version == NULL || !strcmp(openflow_version, "1.0")) {
            pipeline = "standard-1.0";
        } else if (!strcmp(openflow_version, "1.3")) {
            pipeline = "standard-1.3";
        } else {
            AIM_DIE("unexpected OpenFlow version");
        }
    }

    AIM_LOG_INFO("Initializing forwarding pipeline '%s'", pipeline);
    indigo_error_t rv = pipeline_set(pipeline);
    if (rv < 0) {
        AIM_LOG_FATAL("Failed to set pipeline: %s", indigo_strerror(rv));
        return 1;
    }

#if 0
    /* TODO Configuration module installs its own SIGHUP handler. */
    if (ind_cfg_init() < 0) {
        AIM_LOG_FATAL("Failed to initialize Indigo configuration module");
        return 1;
    }
#endif

    if (config_filename) {
        ind_cfg_filename_set(config_filename);
        if (ind_cfg_load() < 0) {
            AIM_LOG_FATAL("Failed to load configuration file");
            return 1;
        }
    }

    if (dpid) {
        indigo_core_dpid_set(dpid);
    }

    /* Enable all modules */

    if (ind_soc_enable_set(1) < 0) {
        AIM_LOG_FATAL("Failed to enable Indigo socket manager");
        return 1;
    }

    if (ind_cxn_enable_set(1) < 0) {
        AIM_LOG_FATAL("Failed to enable Indigo connection manager");
        return 1;
    }

    if (ind_core_enable_set(1) < 0) {
        AIM_LOG_FATAL("Failed to enable Indigo core module");
        return 1;
    }

    of_port_no_t port_no = 1;

    /* Add uplinks from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, uplinks, char *, str) {
            AIM_LOG_MSG("Adding uplink %s (port %d)", str, port_no);
            if (indigo_port_interface_add(str, port_no, NULL)) {
                AIM_LOG_FATAL("Failed to add uplink %s", str);
                return 1;
            }
            ind_ovs_uplink_add(str);
            port_no++;
        }
    }

    /* Add interfaces from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, interfaces, char *, str) {
            AIM_LOG_MSG("Adding interface %s (port %d)", str, port_no);
            if (indigo_port_interface_add(str, port_no, NULL)) {
                AIM_LOG_FATAL("Failed to add interface %s", str);
                return 1;
            }
            port_no++;
        }
    }

    /* Add controllers from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, controllers, char *, str) {
            AIM_LOG_MSG("Adding controller %s", str);

            indigo_cxn_protocol_params_t proto;
            if (parse_controller(str, &proto, OF_TCP_PORT) < 0) {
                AIM_LOG_FATAL("Failed to parse controller string '%s'", str);
                return 1;
            }

            indigo_cxn_config_params_t config = {
                .version = OF_VERSION_1_3,
                .cxn_priority = 0,
                .local = 0,
                .listen = 0,
                .periodic_echo_ms = 2000,
                .reset_echo_count = 3,
            };

            indigo_controller_id_t id;
            if (indigo_controller_add(&proto, &config, &id) < 0) {
                AIM_LOG_FATAL("Failed to add controller %s", str);
                return 1;
            }
        }
    }

    /* Add listening sockets from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, listeners, char *, str) {
            AIM_LOG_MSG("Adding listener %s", str);

            indigo_cxn_protocol_params_t proto;
            if (parse_controller(str, &proto, 6634) < 0) {
                AIM_LOG_FATAL("Failed to parse listener string '%s'", str);
                return 1;
            }

            indigo_cxn_config_params_t config = {
                .version = OF_VERSION_1_3,
                .cxn_priority = 0,
                .local = 1,
                .listen = 1,
                .periodic_echo_ms = 0,
                .reset_echo_count = 0,
            };

            indigo_controller_id_t id;
            if (indigo_controller_add(&proto, &config, &id) < 0) {
                AIM_LOG_FATAL("Failed to add listener %s", str);
                return 1;
            }
        }
    }

    of_desc_str_t mfr_desc = "Big Switch Networks";
    ind_core_mfr_desc_set(mfr_desc);

    of_desc_str_t sw_desc = "";
    snprintf(sw_desc, sizeof(sw_desc), "%s", program_version);
    ind_core_sw_desc_set(sw_desc);

    of_desc_str_t hw_desc = "";
    snprintf(hw_desc, sizeof(hw_desc), "%s", program_version);
    ind_core_hw_desc_set(hw_desc);

    of_desc_str_t dp_desc = "";
    char hostname[256];
    char domainname[256];
    if (gethostname(hostname, sizeof(hostname))) {
        sprintf(hostname, "(unknown)");
    }
    if (getdomainname(domainname, sizeof(domainname))) {
        sprintf(domainname, "(unknown)");
    }
    snprintf(dp_desc, sizeof(dp_desc), "%s.%s pid %d",
             hostname, domainname, getpid());
    ind_core_dp_desc_set(dp_desc);

    AIM_LOG_INFO("Datapath description: %s", dp_desc);

    of_serial_num_t serial_num = "";
    ind_core_serial_num_set(serial_num);

    /* The SIGHUP handler triggers sighup_callback to run in the main loop. */
    if ((sighup_eventfd = eventfd(0, 0)) < 0) {
        AIM_LOG_FATAL("Failed to allocate eventfd");
        abort();
    }
    signal(SIGHUP, sighup);
    if (ind_soc_socket_register(sighup_eventfd, sighup_callback, NULL) < 0) {
        abort();
    }

    /* The SIGTERM handler triggers sigterm_callback to run in the main loop. */
    if ((sigterm_eventfd = eventfd(0, 0)) < 0) {
        AIM_LOG_FATAL("Failed to allocate eventfd");
        abort();
    }
    signal(SIGTERM, sigterm);
    if (ind_soc_socket_register(sigterm_eventfd, sigterm_callback, NULL) < 0) {
        abort();
    }

    {
        char path[UNIX_PATH_MAX];
        snprintf(path, sizeof(path), "/var/run/ivs-ucli.%s.sock", datapath_name);
        ivs_cli_init(path);
    }

    /* Start handling upcalls */
    ind_ovs_enable();

    ind_soc_select_and_run(-1);

    AIM_LOG_MSG("Stopping %s", program_version);

    ind_core_finish();
    ind_ovs_finish();
    ind_cxn_finish();
    ind_soc_finish();

    return 0;
}

static int
ivs_loci_logger(loci_log_level_t level,
                const char *fname, const char *file, int line,
                const char *format, ...)
{
    int log_flag;
    switch (level) {
    case LOCI_LOG_LEVEL_TRACE:
        log_flag = AIM_LOG_FLAG_TRACE;
        break;
    case LOCI_LOG_LEVEL_VERBOSE:
        log_flag = AIM_LOG_FLAG_VERBOSE;
        break;
    case LOCI_LOG_LEVEL_INFO:
        log_flag = AIM_LOG_FLAG_INFO;
        break;
    case LOCI_LOG_LEVEL_WARN:
        log_flag = AIM_LOG_FLAG_WARN;
        break;
    case LOCI_LOG_LEVEL_ERROR:
        log_flag = AIM_LOG_FLAG_ERROR;
        break;
    default:
        log_flag = AIM_LOG_FLAG_MSG;
        break;
    }

    va_list ap;
    va_start(ap, format);
    aim_log_vcommon(&AIM_LOG_STRUCT, log_flag, NULL, 0, fname, file, line, format, ap);
    va_end(ap);

    return 0;
}
