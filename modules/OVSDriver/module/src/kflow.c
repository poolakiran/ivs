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

#include "ovs_driver_int.h"
#include "murmur/murmur.h"
#include <pthread.h>

#define IND_OVS_KFLOW_EXPIRATION_MS 2345
#define NUM_KFLOW_BUCKETS 8192

#ifndef NDEBUG
#define NUM_KFLOW_MASK_TESTS 2
#else
#define NUM_KFLOW_MASK_TESTS 0
#endif

static void test_kflow_mask(struct ind_ovs_kflow *kflow);

static struct list_head ind_ovs_kflows;
static struct list_head ind_ovs_kflow_buckets[NUM_KFLOW_BUCKETS];
static struct xbuf ind_ovs_kflow_stats_xbuf;
static struct stats_writer *ind_ovs_kflow_stats_writer;

DEBUG_COUNTER(add, "ovsdriver.kflow.add", "Kernel flow added");
DEBUG_COUNTER(add_invalid_port, "ovsdriver.kflow.add_invalid_port",
              "Kernel flow add failed due to invalid port number");
DEBUG_COUNTER(add_kflow_limit, "ovsdriver.kflow.add_kflow_limit",
              "Kernel flow add failed due to per-port limit");
DEBUG_COUNTER(add_exists, "ovsdriver.kflow.add_exists",
              "Kernel flow add skipped because it already exists");
DEBUG_COUNTER(add_pipeline_failed, "ovsdriver.kflow.add_pipeline_failed",
              "Kernel flow add failed due an error from the forwarding pipeline");
DEBUG_COUNTER(add_kernel_failed, "ovsdriver.kflow.add_kernel_failed",
              "Kernel flow add failed due an error from the kernel");
DEBUG_COUNTER(sync_stats, "ovsdriver.kflow.sync_stats",
              "Synchronized statistics from a kernel flow");
DEBUG_COUNTER(sync_stats_failed, "ovsdriver.kflow.sync_stats_failed",
              "Failed to synchronize statistics from a kernel flow");
DEBUG_COUNTER(delete, "ovsdriver.kflow.delete", "Kernel flow deleted");
DEBUG_COUNTER(revalidate, "ovsdriver.kflow.revalidate", "Kernel flow revalidated");
DEBUG_COUNTER(revalidate_mask_changed, "ovsdriver.kflow.revalidate_mask_changed",
              "Kernel flow mask changed when revalidating");
DEBUG_COUNTER(revalidate_actions_changed, "ovsdriver.kflow.revalidate_actions_changed",
              "Kernel flow actions changed when revalidating");
DEBUG_COUNTER(revalidate_kernel_failed, "ovsdriver.kflow.revalidate_kernel_failed",
              "Revalidating a kernel flow add failed due an error from the kernel");
DEBUG_COUNTER(revalidate_time, "ovsdriver.kflow.revalidate_time",
              "Time in microseconds spent revalidating kernel flows");

static inline uint32_t
key_hash(const struct nlattr *key)
{
    return murmur_hash(nla_data(key), nla_len(key), ind_ovs_salt);
}

indigo_error_t
ind_ovs_kflow_add(const struct nlattr *key)
{
    debug_counter_inc(&add);

    /* Check input port accounting */
    struct nlattr *in_port_attr = nla_find(nla_data(key), nla_len(key), OVS_KEY_ATTR_IN_PORT);
    assert(in_port_attr);
    uint32_t in_port = nla_get_u32(in_port_attr);
    struct ind_ovs_port *port = ind_ovs_ports[in_port];
    if (port == NULL) {
        /* The port was deleted after the packet was queued to userspace. */
        debug_counter_inc(&add_invalid_port);
        return INDIGO_ERROR_NONE;
    }

    if (!ind_ovs_benchmark_mode && port->num_kflows >= IND_OVS_MAX_KFLOWS_PER_PORT) {
        LOG_WARN("port %d (%s) exceeded allowed number of kernel flows", in_port, port->ifname);
        debug_counter_inc(&add_kflow_limit);
        return INDIGO_ERROR_RESOURCE;
    }

    uint32_t hash = key_hash(key);

    /*
     * Check that the kernel flow table doesn't already include this flow.
     * In the time between the packet being queued to userspace and the kflow
     * being inserted many more packets matching this kflow could have been
     * enqueued.
     */
    struct list_head *bucket = &ind_ovs_kflow_buckets[hash % NUM_KFLOW_BUCKETS];
    struct list_links *cur;
    LIST_FOREACH(bucket, cur) {
        struct ind_ovs_kflow *kflow2 = container_of(cur, bucket_links, struct ind_ovs_kflow);
        if (nla_len(kflow2->key) == nla_len(key) &&
            memcmp(nla_data(kflow2->key), nla_data(key), nla_len(key)) == 0) {
            debug_counter_inc(&add_exists);
            return INDIGO_ERROR_NONE;
        }
    }

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key((struct nlattr *)key, &pkey);

    struct ind_ovs_parsed_key mask;
    memset(&mask, 0, sizeof(mask));

    struct ind_ovs_kflow *kflow = aim_malloc(sizeof(*kflow) + key->nla_len);

    struct xbuf *stats = &ind_ovs_kflow_stats_xbuf;
    xbuf_reset(stats);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_NEW);
    nla_put(msg, OVS_FLOW_ATTR_KEY, nla_len(key), nla_data(key));
    struct nlattr *actions = nla_nest_start(msg, OVS_FLOW_ATTR_ACTIONS);

    struct action_context actx;
    action_context_init(&actx, &pkey, &mask, msg);

    indigo_error_t err = pipeline_process(&pkey, &mask, stats, &actx);
    if (err < 0) {
        aim_free(kflow);
        ind_ovs_nlmsg_freelist_free(msg);
        debug_counter_inc(&add_pipeline_failed);
        return err;
    }

    ind_ovs_nla_nest_end(msg, actions);

    if (!ind_ovs_disable_megaflows) {
        struct nlattr *mask_attr = nla_nest_start(msg, OVS_FLOW_ATTR_MASK);
        assert(ATTR_BITMAP_TEST(mask.populated, OVS_KEY_ATTR_ETHERTYPE));
        ind_ovs_emit_key(&mask, msg, true);
        ind_ovs_nla_nest_end(msg, mask_attr);
    }

    /* Copy actions before ind_ovs_transact() frees msg */
    kflow->actions = aim_malloc(nla_len(actions));
    memcpy(kflow->actions, nla_data(actions), nla_len(actions));
    kflow->actions_len = nla_len(actions);

    if (ind_ovs_transact(msg) < 0) {
        AIM_LOG_ERROR("Failed to insert kernel flow");
        debug_counter_inc(&add_kernel_failed);
        aim_free(kflow->actions);
        aim_free(kflow);
        return INDIGO_ERROR_UNKNOWN;
    }

    kflow->last_used = monotonic_us()/1000;
    kflow->in_port = in_port;
    kflow->stats.packets = 0;
    kflow->stats.bytes = 0;
    kflow->mask = mask;

    memcpy(kflow->key, key, key->nla_len);

    struct stats_handle *stats_handles = xbuf_data(stats);
    int num_stats_handles = xbuf_length(stats) / sizeof(*stats_handles);

    kflow->num_stats_handles = num_stats_handles;
    kflow->stats_handles = aim_memdup(stats_handles, num_stats_handles * sizeof(*stats_handles));

    list_push(&ind_ovs_kflows, &kflow->global_links);
    list_push(bucket, &kflow->bucket_links);

    port->num_kflows++;

    test_kflow_mask(kflow);

    return INDIGO_ERROR_NONE;
}

void
ind_ovs_kflow_sync_stats(struct ind_ovs_kflow *kflow)
{
    debug_counter_inc(&sync_stats);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_GET);
    nla_put(msg, OVS_FLOW_ATTR_KEY, nla_len(kflow->key), nla_data(kflow->key));

    struct nlmsghdr *reply;
    if (ind_ovs_transact_reply(msg, &reply) < 0) {
        LOG_WARN("failed to sync flow stats");
        debug_counter_inc(&sync_stats_failed);
        return;
    }

    struct nlattr *attrs[OVS_FLOW_ATTR_MAX+1];
    if (genlmsg_parse(reply, sizeof(struct ovs_header),
                      attrs, OVS_FLOW_ATTR_MAX,
                      NULL) < 0) {
        LOG_ERROR("failed to parse datapath message");
        abort();
    }

    struct nlattr *stats_attr = attrs[OVS_FLOW_ATTR_STATS];
    if (stats_attr) {
        struct ovs_flow_stats *stats = nla_data(stats_attr);

        uint64_t packet_diff = stats->n_packets - kflow->stats.packets;
        uint64_t byte_diff = stats->n_bytes - kflow->stats.bytes;

        if (packet_diff > 0 || byte_diff > 0) {
            int i;
            for (i = 0; i < kflow->num_stats_handles; i++) {
                stats_inc(ind_ovs_kflow_stats_writer,
                          &kflow->stats_handles[i],
                          packet_diff, byte_diff);
            }

            kflow->stats.packets = stats->n_packets;
            kflow->stats.bytes = stats->n_bytes;
        }
    }

    struct nlattr *used_attr = attrs[OVS_FLOW_ATTR_USED];
    if (used_attr) {
        uint64_t used = nla_get_u64(used_attr);
        if (used > kflow->last_used) {
            kflow->last_used = used;
        } else {
            //LOG_WARN("kflow used time went backwards");
        }
    }

    aim_free(reply);
}

/*
 * Delete the given kflow from the kernel flow table and free it.
 * This function should rarely be called directly. Instead use
 * ind_ovs_kflow_invalidate, which can attempt to update the kflow
 * with the correct actions. Deleting an active kflow could cause
 * a flood of upcalls, and inactive kflows will be expired anyway.
 */
static void
ind_ovs_kflow_delete(struct ind_ovs_kflow *kflow)
{
    struct ind_ovs_port *port = ind_ovs_ports[kflow->in_port];
    if (port) {
        port->num_kflows--;
    }

    /*
     * Packets could match the kernel flow in the time between syncing stats
     * and deleting it, but in practice we should not be deleting active flows.
     */
    ind_ovs_kflow_sync_stats(kflow);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_DEL);
    nla_put(msg, OVS_FLOW_ATTR_KEY, nla_len(kflow->key), nla_data(kflow->key));
    (void) ind_ovs_transact(msg);

    list_remove(&kflow->global_links);
    list_remove(&kflow->bucket_links);
    aim_free(kflow->actions);
    aim_free(kflow->stats_handles);
    aim_free(kflow);

    debug_counter_inc(&delete);
}

/*
 * Run the given kflow's key through the flowtable. If it matches a flow
 * then update the actions, otherwise delete it.
 */
void
ind_ovs_kflow_invalidate(struct ind_ovs_kflow *kflow)
{
    debug_counter_inc(&revalidate);

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key(kflow->key, &pkey);

    struct ind_ovs_parsed_key mask;
    memset(&mask, 0, sizeof(mask));

    struct xbuf *stats = &ind_ovs_kflow_stats_xbuf;
    xbuf_reset(stats);

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_SET);
    nla_put(msg, OVS_FLOW_ATTR_KEY, nla_len(kflow->key), nla_data(kflow->key));
    struct nlattr *actions = nla_nest_start(msg, OVS_FLOW_ATTR_ACTIONS);

    struct action_context actx;
    action_context_init(&actx, &pkey, &mask, msg);

    indigo_error_t err = pipeline_process(&pkey, &mask, stats, &actx);
    if (err < 0) {
        ind_ovs_kflow_delete(kflow);
        ind_ovs_nlmsg_freelist_free(msg);
        return;
    }

    ind_ovs_nla_nest_end(msg, actions);

    if (memcmp(&mask, &kflow->mask, sizeof(mask))) {
        LOG_VERBOSE("Mask changed, deleting kernel flow");
        debug_counter_inc(&revalidate_mask_changed);
        ind_ovs_nlmsg_freelist_free(msg);
        ind_ovs_kflow_delete(kflow);
        return;
    }

    struct stats_handle *stats_handles = xbuf_data(stats);
    int num_stats_handles = xbuf_length(stats) / sizeof(*stats_handles);
    size_t stats_handles_len = num_stats_handles * sizeof(*stats_handles);
    if (num_stats_handles != kflow->num_stats_handles ||
            memcmp(stats_handles, kflow->stats_handles, stats_handles_len)) {
        /* Synchronize stats to previous OpenFlow flows */
        ind_ovs_kflow_sync_stats(kflow);
        if (num_stats_handles != kflow->num_stats_handles) {
            kflow->num_stats_handles = num_stats_handles;
            kflow->stats_handles = aim_realloc(kflow->stats_handles, stats_handles_len);
        }
        memcpy(kflow->stats_handles, stats_handles, stats_handles_len);
    }

    bool actions_changed = nla_len(actions) != kflow->actions_len ||
        memcmp(nla_data(actions), kflow->actions, nla_len(actions));

    if (actions_changed) {
        debug_counter_inc(&revalidate_actions_changed);

        if (!ind_ovs_disable_megaflows) {
            struct nlattr *mask_attr = nla_nest_start(msg, OVS_FLOW_ATTR_MASK);
            assert(ATTR_BITMAP_TEST(mask.populated, OVS_KEY_ATTR_ETHERTYPE));
            ind_ovs_emit_key(&mask, msg, true);
            ind_ovs_nla_nest_end(msg, mask_attr);
        }

        if (ind_ovs_transact(msg) < 0) {
            LOG_ERROR("Failed to modify kernel flow, deleting it");
            debug_counter_inc(&revalidate_kernel_failed);
            ind_ovs_nlmsg_freelist_free(msg);
            ind_ovs_kflow_delete(kflow);
            return;
        }

        if (actions_changed) {
            kflow->actions = aim_realloc(kflow->actions, nla_len(actions));
            memcpy(kflow->actions, nla_data(actions), nla_len(actions));
            kflow->actions_len = nla_len(actions);
        }
    } else {
        ind_ovs_nlmsg_freelist_free(msg);
    }

    test_kflow_mask(kflow);
}

/*
 * Invalidate all kernel flows
 */
void
ind_ovs_kflow_invalidate_all(void)
{
    if (list_empty(&ind_ovs_kflows)) {
        return;
    }

    uint64_t start_time = monotonic_us();
    int count = 0;
    struct list_links *cur, *next;
    LIST_FOREACH_SAFE(&ind_ovs_kflows, cur, next) {
        struct ind_ovs_kflow *kflow = container_of(cur, global_links, struct ind_ovs_kflow);
        ind_ovs_kflow_invalidate(kflow);
        count++;
    }
    uint64_t end_time = monotonic_us();
    uint64_t elapsed = end_time - start_time;
    LOG_VERBOSE("invalidated %d kernel flows in %d us (%.3f us/flow)",
                count, elapsed, (float)elapsed/count);
    debug_counter_add(&revalidate_time, elapsed);
}

/*
 * Delete all kflows that haven't been used in more than
 * IND_OVS_KFLOW_EXPIRATION_MS milliseconds.
 *
 * This has the side effect of synchronizing stats.
 *
 * TODO do this more efficiently, spread out over multiple steps.
 */
void
ind_ovs_kflow_expire(void)
{
    uint64_t cur_time = monotonic_us()/1000;
    struct list_links *cur, *next;
    LIST_FOREACH_SAFE(&ind_ovs_kflows, cur, next) {
        struct ind_ovs_kflow *kflow = container_of(cur, global_links, struct ind_ovs_kflow);

        /* Don't bother checking kflows that can't have expired yet. */
        if ((cur_time - kflow->last_used) < IND_OVS_KFLOW_EXPIRATION_MS) {
            continue;
        }

        /* Might have expired, ask the kernel for the real last_used time. */
        ind_ovs_kflow_sync_stats(kflow);

        if ((cur_time - kflow->last_used) >= IND_OVS_KFLOW_EXPIRATION_MS) {
            LOG_VERBOSE("expiring kflow");
            ind_ovs_kflow_delete(kflow);
        }
    }
}

/* Overwrite the bits in 'key' where 'mask' is 0 with random values */
static void
randomize_unmasked(char *key, const char *mask, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (~mask[i]) {
            key[i] ^= rand() & ~mask[i];
        }
    }
}

/*
 * Self test for megaflows
 *
 * In debug builds, this function is run whenever we add or modify a kernel
 * flow. It double-checks the validity of the mask by randomizing the parts of
 * the key where the mask is zero. If changing any of those bits causes the
 * output of the pipeline to change then the mask was incorrect.
 */
static void
test_kflow_mask(struct ind_ovs_kflow *kflow)
{
    int i;
    for (i = 0; i < NUM_KFLOW_MASK_TESTS; i++) {
        LOG_VERBOSE("Testing kflow mask (iteration %d)", i);

        struct ind_ovs_parsed_key pkey;
        ind_ovs_parse_key((struct nlattr *)kflow->key, &pkey);
        uint64_t populated = pkey.populated;

        randomize_unmasked((char *)&pkey, (char *)&kflow->mask, sizeof(pkey));
        pkey.populated = populated;

        struct ind_ovs_parsed_key mask;
        memset(&mask, 0, sizeof(mask));

        struct xbuf *stats = &ind_ovs_kflow_stats_xbuf;
        xbuf_reset(stats);

        struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_NEW);
        struct nlattr *actions = nla_nest_start(msg, OVS_FLOW_ATTR_ACTIONS);

        struct action_context actx;
        action_context_init(&actx, &pkey, &mask, msg);

        indigo_error_t err = pipeline_process(&pkey, &mask, stats, &actx);
        if (err < 0) {
            abort();
        }

        ind_ovs_nla_nest_end(msg, actions);

        LOG_VERBOSE("Resulting actions:");
        ind_ovs_dump_msg(nlmsg_hdr(msg));

        assert(nla_len(actions) == kflow->actions_len);
        assert(!memcmp(nla_data(actions), kflow->actions, nla_len(actions)));
        assert(!memcmp(&mask, &kflow->mask, sizeof(mask)));
        assert(xbuf_length(stats) == kflow->num_stats_handles * sizeof(struct stats_handle));
        assert(!memcmp(xbuf_data(stats), kflow->stats_handles, xbuf_length(stats)));

        ind_ovs_nlmsg_freelist_free(msg);
    }
}

void
ind_ovs_kflow_module_init(void)
{
    list_init(&ind_ovs_kflows);

    int i;
    for (i = 0; i < NUM_KFLOW_BUCKETS; i++) {
        list_init(&ind_ovs_kflow_buckets[i]);
    }

    xbuf_init(&ind_ovs_kflow_stats_xbuf);

    ind_ovs_kflow_stats_writer = stats_writer_create();
}
