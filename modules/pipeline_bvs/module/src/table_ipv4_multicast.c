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
#include <indigo/of_state_manager.h>
#include <SocketManager/socketmanager.h>
#include <debug_counter/debug_counter.h>
#include <timer_wheel/timer_wheel.h>
#include "pipeline_bvs_int.h"

#define TEMPLATE_NAME ipv4_multicast_hashtable
#define TEMPLATE_OBJ_TYPE struct ipv4_multicast_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *ipv4_multicast_table;
static const indigo_core_gentable_ops_t ipv4_multicast_ops;
static bighash_table_t *ipv4_multicast_hashtable;
static timer_wheel_t *ipv4_multicast_tw;

static void cleanup_value(struct ipv4_multicast_value *value);

DEBUG_COUNTER(idle_notification_counter,
    "ipv4_multicast.idle_notification",
    "ipv4_multicast_idle notification sent to the controller");

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct ipv4_multicast_key *key)
{
    of_object_t tlv;
    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) != OF_ERROR_NONE ) {
        AIM_LOG_ERROR("expected multicast_interface_id key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_MULTICAST_INTERFACE_ID) {
        of_bsn_tlv_multicast_interface_id_value_get(&tlv, &key->multicast_interface_id);
    } else {
        AIM_LOG_ERROR("expected multicast_interface_id key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) != OF_ERROR_NONE) {
        AIM_LOG_ERROR("expected vrf key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_VRF) {
        of_bsn_tlv_vrf_value_get(&tlv, &key->vrf);
    } else {
        AIM_LOG_ERROR("expected vrf key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv, &key->ipv4);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) != OF_ERROR_NONE) {
        return INDIGO_ERROR_NONE;
    }

    /* Optional ipv4_src */
    if (tlv.object_id == OF_BSN_TLV_IPV4_SRC) {
        of_bsn_tlv_ipv4_value_get(&tlv, &key->ipv4_src);
    } else {
        AIM_LOG_ERROR("expected ipv4_src key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == OF_ERROR_NONE) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct ipv4_multicast_value *value)
{
    int rv;
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference value TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    OF_LIST_BSN_TLV_ITER(tlvs, &tlv, rv) {
        switch(tlv.object_id) {
        case OF_BSN_TLV_REFERENCE: {
            of_object_t refkey;
            uint16_t table_id;
            of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
            of_bsn_tlv_reference_key_bind(&tlv, &refkey);
            if (table_id == pipeline_bvs_table_multicast_replication_group_id) {
                value->multicast_replication_group = pipeline_bvs_table_multicast_replication_group_acquire(&refkey);
                if (value->multicast_replication_group == NULL) {
                    AIM_LOG_ERROR("Nonexistent multicast_replication_group in multicast_replication multicast_replication table");
                    cleanup_value(value);
                    return INDIGO_ERROR_PARAM;
                }
            } else {
                AIM_LOG_ERROR("unsupported gentable reference in multicast_replication table");
                cleanup_value(value);
                return INDIGO_ERROR_PARAM;
            }
            break;
        }

        /* ignore below TLVs */
        case OF_BSN_TLV_MULTICAST_INTERFACE_ID: /* fall-through */
        case OF_BSN_TLV_PORT: /* fall-through */
        case OF_BSN_TLV_DROP:
            break;
        default:
            return INDIGO_ERROR_PARAM;
        }
    }

    return INDIGO_ERROR_NONE;
}

static void
cleanup_value(struct ipv4_multicast_value *value)
{
    if (value->multicast_replication_group) {
        pipeline_bvs_table_multicast_replication_group_release(value->multicast_replication_group);
        value->multicast_replication_group = NULL;
    }
}

static indigo_error_t
ipv4_multicast_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct ipv4_multicast_key key;
    struct ipv4_multicast_value value;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &value)) < 0) {
        return rv;
    }

    struct ipv4_multicast_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    ipv4_multicast_hashtable_insert(ipv4_multicast_hashtable, entry);

    stats_alloc(&entry->stats_handle);

    if (entry->value.idle_timeout) {
        timer_wheel_insert(ipv4_multicast_tw, &entry->timer_entry,
                           INDIGO_CURRENT_TIME + entry->value.idle_timeout);
    }

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ipv4_multicast_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct ipv4_multicast_value new_value;
    struct ipv4_multicast_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value)) < 0) {
        return rv;
    }

    if (entry->value.idle_timeout) {
        timer_wheel_remove(ipv4_multicast_tw, &entry->timer_entry);
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    if (entry->value.idle_timeout) {
        timer_wheel_insert(ipv4_multicast_tw, &entry->timer_entry,
                           INDIGO_CURRENT_TIME + entry->value.idle_timeout);
    }

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ipv4_multicast_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct ipv4_multicast_entry *entry = entry_priv;
    bighash_remove(ipv4_multicast_hashtable, &entry->hash_entry);
    if (entry->value.idle_timeout) {
        timer_wheel_remove(ipv4_multicast_tw, &entry->timer_entry);
    }
    cleanup_value(&entry->value);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
ipv4_multicast_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    struct ipv4_multicast_entry *entry = entry_priv;
    struct stats stat;
    stats_get(&entry->stats_handle, &stat);

    /* rx_packets */
    {
        of_bsn_tlv_rx_packets_t tlv;
        of_bsn_tlv_rx_packets_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, &tlv);
        of_bsn_tlv_rx_packets_value_set(&tlv, stat.packets);
    }
    /* rx_bytes */
    {
        of_bsn_tlv_rx_bytes_t tlv;
        of_bsn_tlv_rx_bytes_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, &tlv);
        of_bsn_tlv_rx_bytes_value_set(&tlv, stat.bytes);
    }
}

static const indigo_core_gentable_ops_t ipv4_multicast_ops = {
    .add2 = ipv4_multicast_add,
    .modify2 = ipv4_multicast_modify,
    .del2 = ipv4_multicast_delete,
    .get_stats = ipv4_multicast_get_stats,
};

static void
ipv4_multicast_send_idle_notification(struct ipv4_multicast_entry *entry)
{
    AIM_LOG_VERBOSE("Sending idle notification for mc_ifc_id %u vrf %u "
                    "(%{ipv4a}, %{ipv4a})", entry->key.multicast_interface_id,
                    entry->key.vrf, entry->key.ipv4_src, entry->key.ipv4);

    of_version_t version;
    if (indigo_cxn_get_async_version(&version) < 0) {
        /* No controller connected */
        return;
    } else if (version < OF_VERSION_1_4) {
        /* async notification requires OF 1.4+ */
        return;
    }

    of_object_t *notif = of_bsn_generic_async_new(version);
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(version);

    {
        of_str64_t name = "ipv4_multicast_idle";
        of_bsn_generic_async_name_set(notif, name);
    }

    {
        of_bsn_tlv_multicast_interface_id_t *tlv = of_bsn_tlv_multicast_interface_id_new(version);
        of_bsn_tlv_multicast_interface_id_value_set(tlv, entry->key.multicast_interface_id);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_vrf_t *tlv = of_bsn_tlv_vrf_new(version);
        of_bsn_tlv_vrf_value_set(tlv, entry->key.vrf);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(version);
        of_bsn_tlv_ipv4_value_set(tlv, entry->key.ipv4);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(version);
        of_bsn_tlv_ipv4_value_set(tlv, entry->key.ipv4_src);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    AIM_TRUE_OR_DIE(of_bsn_generic_async_tlvs_set(notif, list) == 0,
                    "Cannot set ipv4_multicast_idle notification tlvs");
    of_object_delete(list);

    /* send notification to controller */
    indigo_cxn_send_async_message(notif);
    debug_counter_inc(&idle_notification_counter);
}

static void
ipv4_multicast_hit_check_timer(void *cookie)
{
    timer_wheel_entry_t *timer;
    indigo_time_t now = INDIGO_CURRENT_TIME;
    int ipv4_mc_idls = 0;
    const int max_ipv4_mc_idls = 32;
    struct stats stat;

    while (ipv4_mc_idls < max_ipv4_mc_idls &&
           !ind_soc_should_yield() &&
           (timer = timer_wheel_next(ipv4_multicast_tw, now))) {
        struct ipv4_multicast_entry *entry =
            container_of(timer, timer_entry, struct ipv4_multicast_entry);

        stats_get(&entry->stats_handle, &stat);

        if (entry->last_hit_check_packets == stat.packets) {
            ipv4_multicast_send_idle_notification(entry);
        } else {
            entry->last_hit_check_packets = stat.packets;
        }
        ipv4_mc_idls++;
        timer_wheel_insert(ipv4_multicast_tw, &entry->timer_entry,
                           now + entry->value.idle_timeout);
    }

    /* reregister sooner if more expired entries */
    if (timer_wheel_peek(ipv4_multicast_tw, now)) {
        ind_soc_timer_event_register(ipv4_multicast_hit_check_timer, NULL, 100);
    } else {
        ind_soc_timer_event_register(ipv4_multicast_hit_check_timer, NULL, 1000);
    }
}

void
pipeline_bvs_table_ipv4_multicast_register(void)
{
    indigo_error_t rv;

    ipv4_multicast_hashtable = bighash_table_create(BIGHASH_AUTOGROW);

    /* to host: 2k entries, idle_timeout 180s */
    /* bucket size is (180*1000)ms / (2*1024)entries ~= 88 */
    ipv4_multicast_tw = timer_wheel_create(2*1024, 128 /*should be pow(2) */,
                                           INDIGO_CURRENT_TIME);

    rv = ind_soc_timer_event_register(ipv4_multicast_hit_check_timer, NULL, 1000);
    AIM_ASSERT(rv == INDIGO_ERROR_NONE,
               "Failed to register general query tx timer: %s",
               indigo_strerror(rv));

    indigo_core_gentable_register("ipv4_multicast", &ipv4_multicast_ops, NULL, 128, 128,
                                  &ipv4_multicast_table);
}

void
pipeline_bvs_table_ipv4_multicast_unregister(void)
{
    indigo_core_gentable_unregister(ipv4_multicast_table);

    ind_soc_timer_event_unregister(ipv4_multicast_hit_check_timer, NULL);

    timer_wheel_destroy(ipv4_multicast_tw);

    bighash_table_destroy(ipv4_multicast_hashtable, NULL);
}

struct ipv4_multicast_entry *
pipeline_bvs_table_ipv4_multicast_lookup(uint16_t multicast_interface_id, uint32_t vrf, uint32_t ipv4, uint32_t ipv4_src)
{
    struct ipv4_multicast_key key = { .multicast_interface_id = multicast_interface_id,
                                      .vrf = vrf, .ipv4 = ipv4, .ipv4_src = ipv4_src};
    struct ipv4_multicast_entry *entry = NULL;

    /* (S,G) lookup */
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit (s,g) ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* (*,G) lookup */
    key.ipv4_src = 0;
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit (*,g) ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* default entry lookup */
    AIM_ZERO(key);
    entry = ipv4_multicast_hashtable_first(ipv4_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit default ipv4_multicast entry multicast_interface_id=%u"
                     " vrf=%u ipv4=%08x ipv4_src=%08x",
                     entry->key.multicast_interface_id,
                     entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
        return entry;
    }

    /* Missed multicast lookup */
    packet_trace("Miss ipv4_multicast entry multicast_interface_id=%u"
                 " vrf=%u ipv4=%08x ipv4_src=%08x",
                 entry->key.multicast_interface_id,
                 entry->key.vrf, entry->key.ipv4, entry->key.ipv4_src);
    return entry;
}
