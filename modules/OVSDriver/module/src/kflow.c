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
#include <SocketManager/socketmanager.h>
#include <tcam/tcam.h>

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
static struct nl_sock *kflow_expire_socket;
static struct tcam *megaflow_tcam;

static bool kflow_expire_task_running;

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
DEBUG_COUNTER(hit, "ovsdriver.kflow.hit", "Packet hit in the kernel flow table");
DEBUG_COUNTER(missed, "ovsdriver.kflow.missed", "Packet missed in the kernel flow table");
DEBUG_COUNTER(lost, "ovsdriver.kflow.lost", "Packet lost due to full upcall socket");
DEBUG_COUNTER(mask_hit, "ovsdriver.kflow.mask_hit", "Mask used for flow lookup");
DEBUG_COUNTER(masks, "ovsdriver.kflow.masks", "Number of kernel flow masks");

static inline uint32_t
key_hash(const struct nlattr *key)
{
    return murmur_hash(nla_data(key), nla_len(key), ind_ovs_salt);
}

static struct ind_ovs_kflow *
kflow_lookup(const struct nlattr *key)
{
    uint32_t hash = key_hash(key);

    struct list_head *bucket = &ind_ovs_kflow_buckets[hash % NUM_KFLOW_BUCKETS];
    struct list_links *cur;
    LIST_FOREACH(bucket, cur) {
        struct ind_ovs_kflow *kflow = container_of(cur, bucket_links, struct ind_ovs_kflow);
        if (nla_len(kflow->key) == nla_len(key) &&
            memcmp(nla_data(kflow->key), nla_data(key), nla_len(key)) == 0) {
            return kflow;
        }
    }

    return NULL;
}

/* Find the kflow that would match the given key */
static struct ind_ovs_kflow *
kflow_match(const struct ind_ovs_parsed_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(megaflow_tcam, key);
    if (!tcam_entry) {
        return NULL;
    }

    return container_of(tcam_entry, tcam_entry, struct ind_ovs_kflow);
}

indigo_error_t
ind_ovs_kflow_add(const struct nlattr *key)
{
    if (ind_ovs_hitless) {
        AIM_LOG_VERBOSE("Skipping kflow add during hitless restart");
        return INDIGO_ERROR_NONE;
    }

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

    struct ind_ovs_parsed_key pkey;
    ind_ovs_parse_key((struct nlattr *)key, &pkey);

    /*
     * Check that the kernel flow table doesn't already include this flow.
     * In the time between the packet being queued to userspace and the kflow
     * being inserted many more packets matching this kflow could have been
     * enqueued.
     */
    if (kflow_match(&pkey) != NULL) {
        debug_counter_inc(&add_exists);
        return INDIGO_ERROR_NONE;
    }

    /*
     * HACK do not insert kflows for uplink LLDPs (BVS-4051)
     *
     * This avoids an interaction between hitless upgrade and inband
     * management.
     *
     * IVS created kernel flows for the LLDPs from the leaf switches
     * with an action to send them to userspace. This action contains
     * the netlink PID identifying the socket to send the packets to.
     * Hitless upgrade preserves the kernel flows until the controller
     * does the first VFT sync. So, the LLDPs were being sent to a
     * socket that no longer exists. Therefore IVS didn't get the
     * inband controller IP, it never did a VFT sync, and the kernel
     * flows were never revalidated.
     *
     * We avoid this problem by not installing kernel flows for LLDPs
     * from the leaf. This is not a performance issue because these kflows
     * would normally expire anyway before the next LLDP arrived.
     */
    if (ind_ovs_inband_vlan != VLAN_INVALID &&
            ind_ovs_uplink_check(pkey.in_port) &&
            pkey.ethertype == htons(0x88cc)) {
        return INDIGO_ERROR_NONE;
    }

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

    uint32_t hash = key_hash(key);
    struct list_head *bucket = &ind_ovs_kflow_buckets[hash % NUM_KFLOW_BUCKETS];

    list_push(&ind_ovs_kflows, &kflow->global_links);
    list_push(bucket, &kflow->bucket_links);

    tcam_insert(megaflow_tcam, &kflow->tcam_entry, &pkey, &mask, 0);

    port->num_kflows++;

    test_kflow_mask(kflow);

    return INDIGO_ERROR_NONE;
}

static void
kflow_sync_stats(struct ind_ovs_kflow *kflow, struct nlattr *stats_attr,
                 struct nlattr *used_attr)
{
    debug_counter_inc(&sync_stats);

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

    if (used_attr) {
        uint64_t used = nla_get_u64(used_attr);
        if (used > kflow->last_used) {
            kflow->last_used = used;
        }
    }
}

void
ind_ovs_kflow_sync_stats(struct ind_ovs_kflow *kflow)
{
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

    kflow_sync_stats(kflow, attrs[OVS_FLOW_ATTR_STATS], attrs[OVS_FLOW_ATTR_USED]);
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
    tcam_remove(megaflow_tcam, &kflow->tcam_entry);
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
    if (ind_ovs_hitless) {
        AIM_LOG_VERBOSE("Skipping kflow revalidation during hitless restart");
        return;
    }

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

static int
kflow_expire(struct nl_msg *msg, void *arg)
{
    uint64_t cur_time = monotonic_us()/1000;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[OVS_FLOW_ATTR_MAX+1];
    if (genlmsg_parse(nlh, sizeof(struct ovs_header),
                      attrs, OVS_FLOW_ATTR_MAX, NULL) < 0) {
        abort();
    }

    struct ind_ovs_kflow *kflow = kflow_lookup(attrs[OVS_FLOW_ATTR_KEY]);
    if (kflow) {
        /* Might have expired, ask the kernel for the real last_used time. */
        kflow_sync_stats(kflow, attrs[OVS_FLOW_ATTR_STATS], attrs[OVS_FLOW_ATTR_USED]);

        if ((cur_time - kflow->last_used) >= IND_OVS_KFLOW_EXPIRATION_MS) {
            LOG_VERBOSE("expiring kflow");
            ind_ovs_kflow_delete(kflow);
        }
    }

    return NL_OK;
}

static int
kflow_expire_recv(struct nl_sock *sk, struct sockaddr_nl *nla,
                  unsigned char **buf, struct ucred **creds)
{
    if (ind_soc_should_yield()) {
        return -NLE_AGAIN;
    }

    return nl_recv(sk, nla, buf, creds);
}

/*
 * Delete all kflows that haven't been used in more than
 * IND_OVS_KFLOW_EXPIRATION_MS milliseconds.
 *
 * This has the side effect of synchronizing stats.
 */
static ind_soc_task_status_t
kflow_expire_task(void *cookie)
{
    if (nl_recvmsgs_report(kflow_expire_socket, nl_socket_get_cb(kflow_expire_socket)) == -NLE_AGAIN) {
        return IND_SOC_TASK_CONTINUE;
    }

    kflow_expire_task_running = false;
    return IND_SOC_TASK_FINISHED;
}

static void
update_datapath_stats(void)
{
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_datapath_family, OVS_DP_CMD_GET);

    struct nlmsghdr *reply;
    if (ind_ovs_transact_reply(msg, &reply) < 0) {
        LOG_WARN("failed to get datapath stats");
        return;
    }

    struct nlattr *attrs[OVS_DP_ATTR_MAX+1];
    if (genlmsg_parse(reply, sizeof(struct ovs_header),
                      attrs, OVS_DP_ATTR_MAX,
                      NULL) < 0) {
        LOG_ERROR("failed to parse datapath message");
        abort();
    }

    if (attrs[OVS_DP_ATTR_STATS]) {
        struct ovs_dp_stats *stats = nla_data(attrs[OVS_DP_ATTR_STATS]);
        hit.value = stats->n_hit;
        missed.value = stats->n_missed;
        lost.value = stats->n_lost;
    }

    if (attrs[OVS_DP_ATTR_MEGAFLOW_STATS]) {
        struct ovs_dp_megaflow_stats *megaflow_stats = nla_data(attrs[OVS_DP_ATTR_MEGAFLOW_STATS]);
        mask_hit.value = megaflow_stats->n_mask_hit;
        masks.value = megaflow_stats->n_masks;
    }

    aim_free(reply);
}

/*
 * Register a long running task to delete expired kflows.
 */
void
ind_ovs_kflow_expire(void)
{
    /* Check if a previous task is already running */
    if (kflow_expire_task_running) {
        return;
    }

    update_datapath_stats();

    if (ind_ovs_hitless) {
        AIM_LOG_VERBOSE("Skipping kflow expiration during hitless restart");
        return;
    }

    if (ind_soc_task_register(kflow_expire_task, NULL, IND_SOC_NORMAL_PRIORITY) < 0) {
        AIM_DIE("Failed to create long running task for kflow expiration");
    }

    AIM_ASSERT(kflow_expire_socket != NULL);

    struct nl_msg *msg = nlmsg_alloc();
    struct ovs_header *hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                         ovs_flow_family, sizeof(*hdr),
                                         NLM_F_DUMP, OVS_FLOW_CMD_GET,
                                         OVS_FLOW_VERSION);
    hdr->dp_ifindex = ind_ovs_dp_ifindex;
    if (nl_send_auto(kflow_expire_socket, msg) < 0) {
        abort();
    }

    nlmsg_free(msg);

    nl_socket_modify_cb(kflow_expire_socket, NL_CB_VALID, NL_CB_CUSTOM,
                        kflow_expire, NULL);
    nl_cb_overwrite_recv(nl_socket_get_cb(kflow_expire_socket), kflow_expire_recv);

    kflow_expire_task_running = true;
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

/* Delete all flows from the kernel datapath */
void
ind_ovs_kflow_flush(void)
{
    AIM_ASSERT(list_empty(&ind_ovs_kflows));
    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_flow_family, OVS_FLOW_CMD_DEL);
    if (ind_ovs_transact(msg)) {
        LOG_ERROR("Failed to delete existing flows from datapath");
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

    kflow_expire_socket = ind_ovs_create_nlsock();
    AIM_ASSERT(kflow_expire_socket != NULL);

    megaflow_tcam = tcam_create(sizeof(struct ind_ovs_parsed_key), ind_ovs_salt);
}

#if OVSDRIVER_CONFIG_INCLUDE_UCLI == 1
void
ind_ovs_kflow_print(ucli_context_t *uc, of_port_no_t port_no)
{
    struct list_links *cur, *next;
    char kflow_str[2048];
    LIST_FOREACH_SAFE(&ind_ovs_kflows, cur, next) {
        struct ind_ovs_kflow *kflow = container_of(cur, global_links, struct ind_ovs_kflow);

        if ((port_no != OF_PORT_DEST_NONE) && (port_no != kflow->in_port)) {
            continue;
        }
        ucli_printf(uc, "%s \n", ind_ovs_dump_flow_str(kflow, kflow_str, sizeof(kflow_str)));
    }
}
#endif
