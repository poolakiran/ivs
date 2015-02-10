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

/*
 * Log to controller using syslog
 *
 * When the switch logs a message, this module sends it over UDP to the
 * controller through the inband interface. The datagram is formatted according
 * to RFC 5424.
 *
 * To prevent overloading the controller with log messages, and to prevent any
 * infinite recursion from logs sent during packet processing, we only send
 * INFO and higher messages to the controller and use a ratelimiter.
 *
 * The inband module's LLDP handler tells this code what the IPv6 addresses of
 * the controllers are.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <AIM/aim_log.h>
#include <AIM/aim_error.h>
#include <AIM/aim_rl.h>
#include <OS/os_time.h>

#define MAX_TARGETS 8
#define REMOTE_LOG_LEVELS AIM_LOG_BITS_DEFAULT

static struct sockaddr_storage targets[MAX_TARGETS];
static int num_targets;
static int sock = -1;
static aim_ratelimiter_t ratelimiter;

static int
syslog_severity(aim_log_flag_t flag)
{
    switch (flag) {
    case AIM_LOG_FLAG_MSG: return LOG_INFO;
    case AIM_LOG_FLAG_FATAL: return LOG_CRIT;
    case AIM_LOG_FLAG_ERROR: return LOG_ERR;
    case AIM_LOG_FLAG_WARN: return LOG_WARNING;
    case AIM_LOG_FLAG_INFO: return LOG_INFO;
    case AIM_LOG_FLAG_VERBOSE: return LOG_DEBUG;
    case AIM_LOG_FLAG_TRACE: return LOG_DEBUG;
    case AIM_LOG_FLAG_INTERNAL: return LOG_DEBUG;
    case AIM_LOG_FLAG_BUG: return LOG_DEBUG;
    case AIM_LOG_FLAG_FTRACE: return LOG_DEBUG;
    case AIM_LOG_FLAG_SYSLOG_EMERG: return LOG_EMERG;
    case AIM_LOG_FLAG_SYSLOG_ALERT: return LOG_ALERT;
    case AIM_LOG_FLAG_SYSLOG_CRIT: return LOG_CRIT;
    case AIM_LOG_FLAG_SYSLOG_ERROR: return LOG_ERR;
    case AIM_LOG_FLAG_SYSLOG_WARN: return LOG_WARNING;
    case AIM_LOG_FLAG_SYSLOG_NOTICE: return LOG_NOTICE;
    case AIM_LOG_FLAG_SYSLOG_INFO: return LOG_INFO;
    case AIM_LOG_FLAG_SYSLOG_DEBUG: return LOG_DEBUG;
    default: return LOG_DEBUG;
    }
}

static void
logger(void *cookie, aim_log_flag_t flag, const char *str)
{
    static char buf[1024];

    fputs(str, stderr);

    /* Don't send trace and verbose logs to the controller */
    if (((1 << flag) & REMOTE_LOG_LEVELS) == 0) {
        return;
    }

    if (aim_ratelimiter_limit(&ratelimiter, os_time_monotonic()) < 0) {
        return;
    }

    if (sock == -1) {
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
    }

    /* Chop off timestamp */
    str += 21;

    int priority = syslog_severity(flag) | LOG_DAEMON;

    struct timeval timeval;
    struct tm tm;
    gettimeofday(&timeval, NULL);
    gmtime_r(&timeval.tv_sec, &tm);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &tm);

    char host[256];
    if (getenv("IVS_HOSTNAME") != NULL) {
        /* Set by t6-mininet */
        strncpy(host, getenv("IVS_HOSTNAME"), sizeof(host));
    } else {
        gethostname(host, sizeof(host));
        host[sizeof(host)-1] = 0;
    }

    int pid = getpid();

    int n = snprintf(buf, sizeof(buf), "<%d>1 %s.%06dZ %s ivs %d - - %s",\
                     priority, timestamp, (int)timeval.tv_usec,
                     host, pid, str);

    int i;
    for (i = 0; i < num_targets; i++) {
        sendto(sock, buf, n, 0, (struct sockaddr *)&targets[i], sizeof(targets[i]));
    }
}

void
inband_logger_reset(void)
{
    num_targets = 0;
}

void
inband_logger_add_target(const struct sockaddr_storage *saddr)
{
    AIM_TRUE_OR_DIE(num_targets < MAX_TARGETS);
    targets[num_targets++] = *saddr;
}

void
inband_logger_post_fork(void)
{
    sock = -1;
}

void
inband_logger_init(void)
{
    aim_logf_set_all("logger", logger, NULL);

    /* Ratelimit to 10 log/s, burst size 10 */
    aim_ratelimiter_init(&ratelimiter, 100*1000, 10, NULL);
}
