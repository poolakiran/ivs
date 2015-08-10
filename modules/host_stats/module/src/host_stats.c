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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#define _GNU_SOURCE /* for sched_getaffinity */
#include <sys/errno.h>
#include <unistd.h>
#include <sched.h>
#include <AIM/aim.h>
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <host_stats/host_stats.h>
#include "host_stats_log.h"

static indigo_core_listener_result_t message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg);

void
host_stats_init(void)
{
    indigo_core_message_listener_register(message_listener);
}

void
__host_stats_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}

static void
add_entry(of_object_t *entries, const char *name, const char *fmt, ...)
{
    of_bsn_generic_stats_entry_t entry;
    of_bsn_generic_stats_entry_init(&entry, entries->version, -1, 1);
    if (of_list_bsn_generic_stats_entry_append_bind(entries, &entry)) {
        goto error;
    }

    of_list_bsn_tlv_t tlvs;
    of_bsn_generic_stats_entry_tlvs_bind(&entry, &tlvs);
    of_bsn_tlv_t tlv;

    {
        of_bsn_tlv_name_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)name, .bytes=strlen(name) };
        if (of_bsn_tlv_name_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    va_list ap;
    char buf[1024];
    va_start(ap, fmt);
    int count = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (count < 0) {
        goto error;
    }

    {
        of_bsn_tlv_data_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)buf, .bytes=count };
        if (of_bsn_tlv_data_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    return;

error:
    AIM_LOG_WARN("Failed to append host stats entry '%s'", name);
}

static void
add_file_entry(of_object_t *entries, const char *name, const char *path)
{
    char buf[2048];

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        AIM_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        goto error;
    }

    int count = fread(buf, 1, sizeof(buf), f);

    fclose(f);

    if (count < 0) {
        AIM_LOG_ERROR("Failed to read %s: %s", path, strerror(errno));
        goto error;
    }

    of_bsn_generic_stats_entry_t entry;
    of_bsn_generic_stats_entry_init(&entry, entries->version, -1, 1);
    if (of_list_bsn_generic_stats_entry_append_bind(entries, &entry)) {
        goto error;
    }

    of_list_bsn_tlv_t tlvs;
    of_bsn_generic_stats_entry_tlvs_bind(&entry, &tlvs);
    of_bsn_tlv_t tlv;

    {
        of_bsn_tlv_name_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)name, .bytes=strlen(name) };
        if (of_bsn_tlv_name_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    {
        of_bsn_tlv_data_init(&tlv, tlvs.version, -1, 1);
        if (of_list_bsn_tlv_append_bind(&tlvs, &tlv)) {
            goto error;
        }
        of_octets_t octets = { .data=(uint8_t *)buf, .bytes=count };
        if (of_bsn_tlv_data_value_set(&tlv, &octets) < 0) {
            goto error;
        }
    }

    return;

error:
    AIM_LOG_WARN("Failed to append host stats entry '%s'", name);
}

static bool
exists(const char *filename)
{
    return access(filename, F_OK) == 0;
}

static bool
scanfile(const char *path, int expected, const char *fmt, ...)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        AIM_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        return false;
    }

    va_list ap;
    va_start(ap, fmt);
    int count = vfscanf(f, fmt, ap);
    va_end(ap);

    fclose(f);

    if (count != expected) {
        AIM_LOG_ERROR("Failed to parse %s", path);
    }

    return count == expected;
}

static bool
get_memory_stats(long unsigned int *r_total, long unsigned int *r_free)
{
    const char *path = "/proc/meminfo";
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        AIM_LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
        return false;
    }

    char line[256];
    long unsigned int mem_total = -1;
    long unsigned int mem_free = -1;
    long unsigned int mem_cached = -1;
    long unsigned int mem_available = -1;

    while (!feof(f)) {
        if (!fgets(line, sizeof(line), f)) {
            break;
        }

        char name[64];
        long unsigned int value;

        int ret = sscanf(line, "%64[^:]: %lu kB", name, &value);
        if (ret != 2) {
            continue;
        }

        if (!strcmp(name, "MemTotal")) {
            mem_total = value;
        } else if (!strcmp(name, "MemFree")) {
            mem_free = value;
        } else if (!strcmp(name, "Cached")) {
            mem_cached = value;
        } else if (!strcmp(name, "MemAvailable")) {
            mem_available = value;
        }
    }

    fclose(f);

    if (mem_total == -1) {
        AIM_LOG_ERROR("Could not find MemTotal in %s", path);
        return false;
    }

    *r_total = mem_total;

    if (mem_available != -1) {
        *r_free = mem_available;
    } else if (mem_free != -1 && mem_cached != -1) {
        *r_free = mem_free + mem_cached;
    } else {
        AIM_LOG_ERROR("Could not find MemFree and MemCached in %s", path);
        return false;
    }

    return true;
}

static void
populate_host_stats_entries(of_object_t *entries)
{
    /* Uptime */
    {
        double uptime;
        if (scanfile("/proc/uptime", 1, "%lf", &uptime)) {
            add_entry(entries, "uptime", "%f", uptime);
        }
    }

    /* Load average */
    {
        double avg1, avg5, avg15;
        if (scanfile("/proc/loadavg", 3, "%lf %lf %lf", &avg1, &avg5, &avg15)) {
            add_entry(entries, "load average (1 minute)", "%f", avg1);
            add_entry(entries, "load average (5 minutes)", "%f", avg5);
            add_entry(entries, "load average (15 minutes)", "%f", avg15);
        }
    }

    /* Memory */
    {
        long unsigned int mem_total, mem_free;
        if (get_memory_stats(&mem_total, &mem_free)) {
            add_entry(entries, "memory total", "%lu", mem_total);
            add_entry(entries, "memory free", "%lu", mem_free);
        }
    }

    /* Kernel version */
    add_file_entry(entries, "kernel version", "/proc/version");

    /* Distribution version */
    if (exists("/etc/lsb-release")) {
        add_file_entry(entries, "distribution version", "/etc/lsb-release");
    }

    /* RedHat version */
    if (exists("/etc/redhat-release")) {
        add_file_entry(entries, "redhat version", "/etc/redhat-release");
    }

    {
        /* Number of CPUs */
        cpu_set_t cpuset;
        int num_cpus;
        if (sched_getaffinity(0, sizeof(cpuset), &cpuset) < 0) {
            AIM_LOG_ERROR("Failed to retrieve scheduler affinity: %s", strerror(errno));
            num_cpus = 1;
        } else {
            num_cpus = CPU_COUNT(&cpuset);
        }

        add_entry(entries, "number of CPUs", "%u", num_cpus);

        /* Normalized CPU Load */
        double avg1, avg5, avg15;
        if (scanfile("/proc/loadavg", 3, "%lf %lf %lf", &avg1, &avg5, &avg15)) {
            add_entry(entries, "normalized CPU load (1 minute)", "%f", avg1/num_cpus);
            add_entry(entries, "normalized CPU load (5 minutes)", "%f", avg5/num_cpus);
            add_entry(entries, "normalized CPU load (15 minutes)", "%f", avg15/num_cpus);
        }
    }
}

static indigo_core_listener_result_t
handle_host_stats_request(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    uint32_t xid;
    of_str64_t stats_name;
    of_bsn_generic_stats_request_xid_get(msg, &xid);
    of_bsn_generic_stats_request_name_get(msg, &stats_name);

    if (strcmp(stats_name, "host")) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    of_object_t *reply = of_bsn_generic_stats_reply_new(msg->version);
    of_bsn_generic_stats_reply_xid_set(reply, xid);
    of_object_t entries;
    of_bsn_generic_stats_reply_entries_bind(reply, &entries);

    populate_host_stats_entries(&entries);

    indigo_cxn_send_controller_message(cxn_id, reply);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static indigo_core_listener_result_t
message_listener(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    switch (msg->object_id) {
    case OF_BSN_GENERIC_STATS_REQUEST:
        return handle_host_stats_request(cxn_id, msg);
    default:
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
}
