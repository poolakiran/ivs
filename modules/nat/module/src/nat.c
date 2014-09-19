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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <AIM/aim.h>
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <debug_counter/debug_counter.h>
#include "nat_int.h"
#include "nat_log.h"

struct nat_entry_key {
    uint32_t external_ip;
};

struct nat_entry_value {
    of_mac_addr_t external_mac;
    of_ipv4_t external_netmask;
    of_ipv4_t external_gateway_ip;
    of_mac_addr_t internal_mac;
    of_mac_addr_t internal_gateway_mac;
};

struct nat_entry {
    struct nat_entry_key key;
    struct nat_entry_value value;
};

static indigo_core_gentable_t *nat_table;

static const indigo_core_gentable_ops_t nat_ops;

/* Debug counters */
static debug_counter_t add_success_counter;
static debug_counter_t add_failure_counter;
static debug_counter_t modify_success_counter;
static debug_counter_t modify_failure_counter;
static debug_counter_t delete_success_counter;

void
nat_init(void)
{
    AIM_LOG_VERBOSE("Initializing NAT module");

    indigo_core_gentable_register("nat", &nat_ops, NULL, 4096, 128,
                                  &nat_table);

    debug_counter_register(
        &add_success_counter, "nat.table_add",
        "NAT table entry added by the controller");

    debug_counter_register(
        &add_failure_counter, "nat.table_add_failure",
        "NAT table entry unsuccessfully added by the controller");

    debug_counter_register(
        &modify_success_counter, "nat.table_modify",
        "NAT table entry modified by the controller");

    debug_counter_register(
        &modify_failure_counter, "nat.table_modify_failure",
        "NAT table entry unsuccessfully modified by the controller");

    debug_counter_register(
        &delete_success_counter, "nat.table_delete",
        "NAT table entry deleted by the controller");
}

void
__nat_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
}


/* nat table operations */

static indigo_error_t
nat_parse_key(of_list_bsn_tlv_t *tlvs, struct nat_entry_key *key)
{
    of_bsn_tlv_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_IP) {
        of_bsn_tlv_external_ip_value_get(&tlv.external_ip, &key->external_ip);
    } else {
        AIM_LOG_ERROR("expected external_ip key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_parse_value(of_list_bsn_tlv_t *tlvs, struct nat_entry_value *value)
{
    of_bsn_tlv_t tlv;

    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External MAC */
    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_MAC) {
        of_bsn_tlv_external_mac_value_get(&tlv.external_mac, &value->external_mac);
    } else {
        AIM_LOG_ERROR("expected external_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External netmask */
    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_NETMASK) {
        of_bsn_tlv_external_netmask_value_get(&tlv.external_netmask, &value->external_netmask);
    } else {
        AIM_LOG_ERROR("expected ipv4 external_netmask value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* External gateway IP */
    if (tlv.header.object_id == OF_BSN_TLV_EXTERNAL_GATEWAY_IP) {
        of_bsn_tlv_external_gateway_ip_value_get(&tlv.external_gateway_ip, &value->external_gateway_ip);
    } else {
        AIM_LOG_ERROR("expected external_gateway_ip value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal MAC */
    if (tlv.header.object_id == OF_BSN_TLV_INTERNAL_MAC) {
        of_bsn_tlv_internal_mac_value_get(&tlv.internal_mac, &value->internal_mac);
    } else {
        AIM_LOG_ERROR("expected internal_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Internal gateway MAC */
    if (tlv.header.object_id == OF_BSN_TLV_INTERNAL_GATEWAY_MAC) {
        of_bsn_tlv_internal_gateway_mac_value_get(&tlv.internal_gateway_mac, &value->internal_gateway_mac);
    } else {
        AIM_LOG_ERROR("expected internal_gateway_mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct nat_entry_key key;
    struct nat_entry_value value;
    struct nat_entry *entry;

    rv = nat_parse_key(key_tlvs, &key);
    if (rv < 0) {
        debug_counter_inc(&add_failure_counter);
        return rv;
    }

    rv = nat_parse_value(value_tlvs, &value);
    if (rv < 0) {
        debug_counter_inc(&add_failure_counter);
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    *entry_priv = entry;
    debug_counter_inc(&add_success_counter);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct nat_entry_value value;
    struct nat_entry *entry = entry_priv;

    rv = nat_parse_value(value_tlvs, &value);
    if (rv < 0) {
        debug_counter_inc(&modify_failure_counter);
        return rv;
    }

    entry->value = value;
    entry->stats.internal_port = 1;
    entry->stats.external_port = 2;

    debug_counter_inc(&modify_success_counter);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
nat_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct nat_entry *entry = entry_priv;
    aim_free(entry);
    debug_counter_inc(&delete_success_counter);
    return INDIGO_ERROR_NONE;
}

static void
nat_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* No stats */
}

static const indigo_core_gentable_ops_t nat_ops = {
    .add = nat_add,
    .modify = nat_modify,
    .del = nat_delete,
    .get_stats = nat_get_stats,
};
