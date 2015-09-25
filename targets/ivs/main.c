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
#include <AIM/aim.h>
#include <unistd.h>
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
#include <sys/resource.h>
#include <shared_debug_counter/shared_debug_counter.h>
#include <sys/prctl.h>
#include <execinfo.h>
#include <packet_trace/packet_trace.h>

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

#ifndef BUILD_OS
#define BUILD_OS local
#endif

void ivs_cli_init(const char *path);
void ivs_agent_init(void);

static int
ivs_loci_logger(loci_log_level_t level,
                const char *fname, const char *file, int line,
                const char *format, ...);

static void
logger(void *cookie, aim_log_flag_t flag, const char *str);

const char *ivs_version = "3.5.0";
const char *ivs_build_id = AIM_STRINGIFY(BUILD_ID);
const char *ivs_build_os = AIM_STRINGIFY(BUILD_OS);

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
static biglist_t *internal_ports = NULL;
static uint64_t dpid = 0;
static int use_syslog = 0;
static char *datapath_name = "ivs";
static char *config_filename = NULL;
static char *openflow_version = NULL;
static char *pipeline = NULL;
static char pidfile_path[PATH_MAX];
static bool hitless;

static int count_char(const char *str, char c)
{
    int r = 0;
    while (*str) {
        if (*str == c) {
            r++;
        }
        str++;
    }
    return r;
}

static int
parse_controller(const char *str,
                 indigo_cxn_protocol_params_t *_proto,
                 int default_port)
{
    char buf[128];
    char *strtok_state = NULL;
    char *ip, *port_str;
    struct sockaddr_in sa;

    if (count_char(str, ':') > 1) {
        /* IPv6 */
        indigo_cxn_params_tcp_over_ipv6_t *proto = &_proto->tcp_over_ipv6;
        proto->protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV6;
        strncpy(proto->controller_ip, str, sizeof(proto->controller_ip));
        proto->controller_port = default_port;
        return 0;
    }

    strncpy(buf, str, sizeof(buf));
    strtok_state = buf;

    indigo_cxn_params_tcp_over_ipv4_t *proto = &_proto->tcp_over_ipv4;
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
            OPT_INTERNAL_PORT,
            OPT_HITLESS,
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
            {"internal-port", required_argument, 0, OPT_INTERNAL_PORT },
            {"hitless",     no_argument,       0, OPT_HITLESS },
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
            printf("ivs %s (%s %s)\n", ivs_version, ivs_build_id, ivs_build_os);
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

        case OPT_INTERNAL_PORT:
            internal_ports = biglist_append(internal_ports, optarg);
            break;

        case OPT_HITLESS:
            hitless = true;
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
            printf("  --internal-port=NAME        Create a port with the given name connected to the datapath\n");
            printf("  --hitless                   Preserve kernel flows until controller pushes configuration\n");
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

static void
set_crash_handler(void (*handler)(int))
{
    signal(SIGILL, handler);
    signal(SIGABRT, handler);
    signal(SIGFPE, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
}

static void
crash_handler(int signum)
{
    /* Avoid recursion */
    set_crash_handler(SIG_DFL);

    /* Unblock signal that killed us */
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, signum);
    sigprocmask(SIG_UNBLOCK, &sigset, NULL);

    /* In case of deadlock */
    alarm(1);

    /* It's possible that this signal handler will crash again due to the many
     * signal-unsafe operations. We want the exit status and core for the
     * original crash to be unaffected by this. So, we fork off a new process
     * to log info about the crash and re-raise the signal in the parent.
     */
    if (fork() != 0) {
        raise(signum);
        AIM_LOG_ERROR("Did not die from raise(%d)", signum);
        _exit(1); /* Should not be reached */
    }

    char name[16] = { 0 };
    prctl(PR_GET_NAME, name);
    AIM_SYSLOG_ERROR(
        "ivs <version> (<build> <os>) killed by signal <signal> (<signal name>)",
        "The virtual switch has been unexpectedly killed.",
        "ivs %s (%s %s) killed by signal %d (%s)",
        ivs_version, ivs_build_id, ivs_build_os, signum, strsignal(signum));

    /*
     * Log a backtrace
     *
     * We aren't using backtrace_symbols(3) because it doesn't know the names
     * of static functions. Instead, developers should pass the hex backtrace
     * to addr2line.
     */
    {
        void *bt[64];
        int num_frames = backtrace(bt, AIM_ARRAYSIZE(bt));
        int buflen = num_frames * strlen(" 0x0123456789abcdef") + 1;
        char *buf = aim_malloc(buflen);
        int offset = 0;
        int i;
        for (i = 0; i < num_frames; i++) {
            /* backtrace(3) returns the address of the next instruction after
             * the call. This might not even be in the same function. While
             * hacky, we get much better backtraces by subtracting 1 from the
             * address to put it in the middle of the actual call instruction.
             */
            uintptr_t addr = (uintptr_t)bt[i] - 1;
            offset += snprintf(buf+offset, buflen-offset, " 0x%"PRIx64, addr);
        }
        AIM_LOG_ERROR("backtrace:%s", buf);

        /* If addr2line is installed, use it to log a human readable backtrace */
        char *cmd;
        FILE *tmp = tmpfile();
        if (asprintf(&cmd, "addr2line -p -f -i -s -e /proc/%d/exe >/proc/self/fd/%d 2>&1", getpid(), fileno(tmp)) >= 0) {
            FILE *addr2line = popen(cmd, "w");
            /* Start at 1 to skip the crash_handler frame */
            for (i = 1; i < num_frames; i++) {
                uintptr_t addr = (uintptr_t)bt[i] - 1;
                fprintf(addr2line, "0x%"PRIx64"\n", addr);
            }
            int exitstatus = pclose(addr2line);
            if (exitstatus != 0) {
                if (WIFEXITED(exitstatus)) {
                    if (WEXITSTATUS(exitstatus) == 127) {
                        /* addr2line not installed */
                        AIM_LOG_VERBOSE("addr2line is not installed");
                    } else {
                        AIM_LOG_ERROR("addr2line failed with exit status %d", WEXITSTATUS(exitstatus));
                    }
                }
            } else {
                AIM_LOG_ERROR("symbolic backtrace:");
                char line[1024];
                while (fgets(line, sizeof(line), tmp) != NULL) {
                    *strchrnul(line, '\n') = 0; /* trim newline */
                    if (strcmp(line, "?? ??:0")) {
                        AIM_LOG_ERROR("  %s", line);
                    }
                }
            }
        }
    }

    _exit(0);
}

static void
delete_pidfile(void)
{
    unlink(pidfile_path);
}

static void
create_pidfile(void)
{
    snprintf(pidfile_path, sizeof(pidfile_path), "/var/run/ivs.%s.pid", datapath_name);
    FILE *pidfile = fopen(pidfile_path, "wx");
    if (pidfile == NULL && errno == EEXIST) {
        pidfile = fopen(pidfile_path, "r");
        if (pidfile == NULL) {
            AIM_DIE("Failed to open pidfile %s: %s", pidfile_path, strerror(errno));
        }
        int old_pid;
        if (fscanf(pidfile, "%d", &old_pid) != 1) {
            AIM_DIE("Failed to parse pidfile");
        }
        if (kill(old_pid, 0) == 0) {
            AIM_LOG_ERROR("IVS pid %d is still running", old_pid);
            exit(1);
        }
        unlink(pidfile_path);
        pidfile = freopen(pidfile_path, "wx", pidfile);
        if (pidfile == NULL) {
            AIM_DIE("Failed to open pidfile %s: %s", pidfile_path, strerror(errno));
        }
    } else if (pidfile == NULL) {
        AIM_DIE("Failed to create pidfile: %s", strerror(errno));
    }

    fprintf(pidfile, "%d\n", getpid());
    fclose(pidfile);

    atexit(delete_pidfile);
}

void
read_hardware_version(of_desc_str_t hw_desc)
{
    FILE *f;

    of_desc_str_t sys_vendor;
    f = fopen("/sys/devices/virtual/dmi/id/sys_vendor", "r");
    if (f) {
        if (fgets(sys_vendor, sizeof(sys_vendor), f) == NULL) {
            AIM_LOG_ERROR("Failed to read sys_vendor: %s", strerror(errno));
            strcpy(sys_vendor, "(unknown vendor)");
        }
        *strchrnul(sys_vendor, '\n') = '\0';
        fclose(f);
    } else {
        strcpy(sys_vendor, "(unknown vendor)");
    }

    of_desc_str_t product_name;
    f = fopen("/sys/devices/virtual/dmi/id/product_name", "r");
    if (f) {
        if (fgets(product_name, sizeof(product_name), f) == NULL) {
            AIM_LOG_ERROR("Failed to read product_name: %s", strerror(errno));
            strcpy(product_name, "(unknown product)");
        }
        *strchrnul(product_name, '\n') = '\0';
        fclose(f);
    } else {
        strcpy(product_name, "(unknown product)");
    }

    memset(hw_desc, 0, sizeof(of_desc_str_t));
    snprintf(hw_desc, sizeof(of_desc_str_t), "%s %s", sys_vendor, product_name);
}

int
aim_main(int argc, char* argv[])
{
    set_crash_handler(crash_handler);

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

    core_cfg.stats_check_ms = 900;

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
        openlog("ivs", LOG_NDELAY, LOG_DAEMON);
    }

    create_pidfile();

    aim_logf_set_all("logger", logger, NULL);

    AIM_SYSLOG_INFO(
        "Starting ivs <version> (<build> <os>) pid <pid>",
        "The virtual switch is starting up.",
        "Starting ivs %s (%s %s) pid %d",
        ivs_version, ivs_build_id, ivs_build_os, getpid());

    shared_debug_counter_init();

    /* Increase maximum number of file descriptors */
    struct rlimit rlim = {
        .rlim_cur = SOCKETMANAGER_CONFIG_MAX_SOCKETS,
        .rlim_max = SOCKETMANAGER_CONFIG_MAX_SOCKETS
    };
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        AIM_LOG_WARN("Failed to increase RLIMIT_NOFILE");
    }

    /* Add uplink names from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, uplinks, char *, str) {
            ind_ovs_uplink_add(str);
        }
    }

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

    if (ind_ovs_init(datapath_name, hitless) < 0) {
        AIM_LOG_FATAL("Failed to initialize OVSDriver module");
        return 1;
    }

    pipeline_init();
    inband_init();
    ivs_agent_init();

    if (pipeline == NULL) {
        if (openflow_version == NULL || !strcmp(openflow_version, "1.0")) {
            pipeline = "standard-1.0";
        } else if (!strcmp(openflow_version, "1.3")) {
            pipeline = "standard-1.3";
        } else {
            AIM_DIE("unexpected OpenFlow version");
        }
    }

    AIM_LOG_VERBOSE("Initializing forwarding pipeline '%s'", pipeline);
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

    /* Add uplinks from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, uplinks, char *, str) {
            AIM_LOG_VERBOSE("Adding uplink %s", str);
            if (indigo_port_interface_add(str, OF_PORT_DEST_NONE, NULL)) {
                AIM_LOG_ERROR("Failed to add uplink %s", str);
            }
        }
    }

    /* Add interfaces from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, interfaces, char *, str) {
            AIM_LOG_VERBOSE("Adding interface %s (port %d)", str);
            if (indigo_port_interface_add(str, OF_PORT_DEST_NONE, NULL)) {
                AIM_LOG_ERROR("Failed to add interface %s", str);
            }
        }
    }

    /* Add internal ports from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, internal_ports, char *, str) {
            AIM_LOG_VERBOSE("Adding internal port %s", str);
            if (ind_ovs_port_add_internal(str)) {
                AIM_LOG_ERROR("Failed to add internal port %s", str);
            }
        }
    }

    /* Add controllers from command line */
    {
        biglist_t *element;
        char *str;
        BIGLIST_FOREACH_DATA(element, controllers, char *, str) {
            AIM_LOG_VERBOSE("Adding controller %s", str);

            indigo_cxn_protocol_params_t proto;
            if (parse_controller(str, &proto, OF_TCP_PORT) < 0) {
                AIM_LOG_FATAL("Failed to parse controller string '%s'", str);
                return 1;
            }

            /* HACK - old BCF controllers will reject switches advertising
             * newer OpenFlow versions in their HELLO messages */
            int version = OF_VERSION_1_4;
            if (getenv("IVS_OPENFLOW_VERSION")) {
                version = atoi(getenv("IVS_OPENFLOW_VERSION"));
            }

            indigo_cxn_config_params_t config = {
                .version = version,
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
            AIM_LOG_VERBOSE("Adding listener %s", str);

            indigo_cxn_protocol_params_t proto;
            if (parse_controller(str, &proto, 6634) < 0) {
                AIM_LOG_FATAL("Failed to parse listener string '%s'", str);
                return 1;
            }

            indigo_cxn_config_params_t config = {
                .version = OF_VERSION_1_4,
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

    /* Listen on a unix domain socket */
    {
        indigo_cxn_protocol_params_t proto;
        proto.unx.protocol = INDIGO_CXN_PROTO_UNIX;
        snprintf(proto.unx.unix_path, sizeof(proto.unx.unix_path),
                 "/var/run/ivs-openflow.%s.sock", datapath_name);

        indigo_cxn_config_params_t config = {
            .version = OF_VERSION_1_4,
            .cxn_priority = 0,
            .local = 1,
            .listen = 1,
            .periodic_echo_ms = 0,
            .reset_echo_count = 0,
        };

        indigo_controller_id_t id;
        if (indigo_controller_add(&proto, &config, &id) < 0) {
            AIM_LOG_ERROR("Failed to listen on %s", proto.unx.unix_path);
        }
    }

    of_desc_str_t mfr_desc = "Big Switch Networks";
    ind_core_mfr_desc_set(mfr_desc);

    of_desc_str_t sw_desc = "";
    snprintf(sw_desc, sizeof(sw_desc), "Switch Light Virtual %s %s %s", ivs_version,
             ivs_build_id, ivs_build_os);
    ind_core_sw_desc_set(sw_desc);

    of_desc_str_t hw_desc = "";
    read_hardware_version(hw_desc);
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

    packet_trace_init(datapath_name);

    ind_soc_select_and_run(-1);

    AIM_LOG_MSG("Stopping ivs %s", ivs_version);

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

static int
aim_log_flag_to_syslog_priority(aim_log_flag_t flag)
{
    switch (flag) {
    case AIM_LOG_FLAG_SYSLOG_EMERG: return LOG_EMERG;
    case AIM_LOG_FLAG_SYSLOG_ALERT: return LOG_ALERT;
    case AIM_LOG_FLAG_SYSLOG_CRIT: return LOG_CRIT;
    case AIM_LOG_FLAG_SYSLOG_ERROR: return LOG_ERR;
    case AIM_LOG_FLAG_SYSLOG_WARN: return LOG_WARNING;
    case AIM_LOG_FLAG_SYSLOG_NOTICE: return LOG_NOTICE;
    case AIM_LOG_FLAG_SYSLOG_INFO: return LOG_INFO;
    case AIM_LOG_FLAG_SYSLOG_DEBUG: return LOG_DEBUG;
    default: return -1;
    }
}

static void
logger(void *cookie, aim_log_flag_t flag, const char *str)
{
    /*
     * Log to stderr
     *
     * When running from init this goes to:
     * Ubuntu: /var/log/upstart/ivs.log
     * RHEL/CentOS: systemd journal
     */
    aim_pvs_logf(&aim_pvs_stderr, flag, str);

    /*
     * Send a syslog message to any inband controllers
     */
    inband_log(flag, str);

    /*
     * Send to local syslog if enabled
     */
    if (use_syslog) {
        int priority = aim_log_flag_to_syslog_priority(flag);
        if (priority >= 0) {
            const char *msg = str + 22; /* HACK skip timestamp */
            syslog(priority, "%s", msg);
        }
    }
}
