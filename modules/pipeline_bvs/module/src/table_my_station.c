/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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

#include "pipeline_bvs_int.h"

static struct tcam *my_station_tcam;
static const of_match_fields_t maximum_mask = {
    .eth_dst = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};
static const of_match_fields_t minimum_mask = {
};

static indigo_error_t
parse_key(of_flow_add_t *obj, struct my_station_key *key, struct my_station_key *mask)
{
    of_match_t match;
    if (of_flow_add_match_get(obj, &match) < 0) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    if (!pipeline_bvs_check_tcam_mask(&match.masks, &minimum_mask, &maximum_mask)) {
        return INDIGO_ERROR_BAD_MATCH;
    }

    uint16_t priority;
    of_flow_add_priority_get(obj, &priority);
    if (priority != 0) {
        return INDIGO_ERROR_COMPAT;
    }

    key->mac = match.fields.eth_dst;
    mask->mac = match.masks.eth_dst;

    key->pad = mask->pad = 0;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_my_station_entry_create(
    void *table_priv, indigo_cxn_id_t cxn_id, of_flow_add_t *obj,
    indigo_cookie_t flow_id, void **entry_priv)
{
    indigo_error_t rv;
    struct my_station_entry *entry = aim_zmalloc(sizeof(*entry));
    struct my_station_key key;
    struct my_station_key mask;

    rv = parse_key(obj, &key, &mask);
    if (rv < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create my_station entry mac=%{mac}/%{mac}", &key.mac, &mask.mac);

    tcam_insert(my_station_tcam, &entry->tcam_entry, &key, &mask, 0);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_my_station_entry_modify(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    of_flow_modify_strict_t *obj)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_my_station_entry_delete(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    struct my_station_entry *entry = entry_priv;

    tcam_remove(my_station_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_my_station_entry_stats_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    indigo_fi_flow_stats_t *flow_stats)
{
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
pipeline_bvs_table_my_station_entry_hit_status_get(
    void *table_priv, indigo_cxn_id_t cxn_id, void *entry_priv,
    bool *hit_status)
{
    return INDIGO_ERROR_NOT_SUPPORTED;
}

static const indigo_core_table_ops_t table_ops = {
    .entry_create = pipeline_bvs_table_my_station_entry_create,
    .entry_modify = pipeline_bvs_table_my_station_entry_modify,
    .entry_delete = pipeline_bvs_table_my_station_entry_delete,
    .entry_stats_get = pipeline_bvs_table_my_station_entry_stats_get,
    .entry_hit_status_get = pipeline_bvs_table_my_station_entry_hit_status_get,
};

void
pipeline_bvs_table_my_station_register(void)
{
    my_station_tcam = tcam_create(sizeof(struct my_station_key), ind_ovs_salt);
    indigo_core_table_register(TABLE_ID_MY_STATION, "my_station", &table_ops, NULL);
}

void
pipeline_bvs_table_my_station_unregister(void)
{
    indigo_core_table_unregister(TABLE_ID_MY_STATION);
    tcam_destroy(my_station_tcam);
}

struct my_station_entry *
pipeline_bvs_table_my_station_lookup(const uint8_t *mac)
{
    struct my_station_key key = {
        .pad = 0,
    };
    memcpy(&key.mac, mac, OF_MAC_ADDR_BYTES);

    struct tcam_entry *tcam_entry = tcam_match(my_station_tcam, &key);
    if (tcam_entry) {
        struct my_station_entry *entry = container_of(tcam_entry, tcam_entry, struct my_station_entry);
        const struct my_station_key *entry_key = tcam_entry->key;
        const struct my_station_key *entry_mask = tcam_entry->mask;
        AIM_LOG_VERBOSE("Hit my_station entry mac=%{mac}/%{mac}", &entry_key->mac, &entry_mask->mac);
        return entry;
    } else {
        AIM_LOG_VERBOSE("Miss my_station entry mac=%{mac}", &key.mac);
        return NULL;
    }
}
