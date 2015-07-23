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

#include "pipeline_bvs_int.h"

#define PORT_BLOCK_TABLE_SIZE (SLSHARED_CONFIG_OF_PORT_MAX+1)

struct port_block_entry {
    bool inuse;
    uint64_t switch_generation_id;
    uint64_t controller_generation_id;
};

struct port_block_key {
    uint32_t port;
};

struct port_block_value {
    uint64_t controller_generation_id;
};

static struct port_block_entry port_block_entries[PORT_BLOCK_TABLE_SIZE];

static indigo_core_gentable_t *port_block_table;
static const indigo_core_gentable_ops_t port_block_ops;
uint16_t pipeline_bvs_table_port_block_id;

void
pipeline_bvs_table_port_block_register(void)
{
    indigo_core_gentable_register("port_block", &port_block_ops, NULL, PORT_BLOCK_TABLE_SIZE, 256,
                                  &port_block_table);
    pipeline_bvs_table_port_block_id = indigo_core_gentable_id(port_block_table);
}

void
pipeline_bvs_table_port_block_unregister(void)
{
    indigo_core_gentable_unregister(port_block_table);
}

/* port_block table operations */

static indigo_error_t
port_block_parse_key(of_list_bsn_tlv_t *tlvs, struct port_block_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_PORT) {
        of_bsn_tlv_port_value_get(&tlv, &key->port);
    } else {
        AIM_LOG_ERROR("expected port key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }


    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_block_parse_value(of_list_bsn_tlv_t *tlvs, struct port_block_value *value)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_GENERATION_ID) {
        of_bsn_tlv_generation_id_value_get(&tlv, &value->controller_generation_id);
    } else {
        AIM_LOG_ERROR("expected generation_id value TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_block_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct port_block_key key;
    struct port_block_value value;
    struct port_block_entry *entry;

    rv = port_block_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = port_block_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    if (key.port >= PORT_BLOCK_TABLE_SIZE) {
        AIM_LOG_ERROR("Invalid port number %u", key.port);
        return INDIGO_ERROR_PARAM;
    }

    entry = &port_block_entries[key.port];
    entry->inuse = true;
    entry->controller_generation_id = value.controller_generation_id;
    entry->switch_generation_id = value.controller_generation_id;

    AIM_LOG_VERBOSE("port_block add port=%u controller=0x%"PRIx64" switch=0x%"PRIx64,
                    key.port, entry->controller_generation_id, entry->switch_generation_id);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_block_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct port_block_value value;
    struct port_block_entry *entry = entry_priv;
    uint32_t port = entry - port_block_entries;

    rv = port_block_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry->controller_generation_id = value.controller_generation_id;

    AIM_LOG_VERBOSE("port_block modify port=%u controller=0x%"PRIx64" switch=0x%"PRIx64,
                    port, entry->controller_generation_id, entry->switch_generation_id);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_block_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct port_block_entry *entry = entry_priv;
    uint32_t port = entry - port_block_entries;
    entry->inuse = false;
    entry->controller_generation_id = 0;
    entry->switch_generation_id = 0;
    AIM_LOG_VERBOSE("port_block delete port=%u", port);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
port_block_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    struct port_block_entry *entry = entry_priv;
    of_bsn_tlv_t tlv;

    of_bsn_tlv_generation_id_init(&tlv, stats->version, -1, 1);
    of_list_bsn_tlv_append_bind(stats, &tlv);
    of_bsn_tlv_generation_id_value_set(&tlv, entry->switch_generation_id);
}

static const indigo_core_gentable_ops_t port_block_ops = {
    .add2 = port_block_add,
    .modify2 = port_block_modify,
    .del2 = port_block_delete,
    .get_stats = port_block_get_stats,
};


/*
 * Return true if the port_block gentable allows this port to be used
 */
bool
pipeline_bvs_table_port_block_check(uint32_t port)
{
    AIM_TRUE_OR_DIE(port < PORT_BLOCK_TABLE_SIZE);
    struct port_block_entry *entry = &port_block_entries[port];
    packet_trace("port_block entry port=%u inuse=%d controller=0x%"PRIx64" switch=0x%"PRIx64,
                 port, entry->inuse, entry->controller_generation_id, entry->switch_generation_id);
    return !entry->inuse || (entry->controller_generation_id == entry->switch_generation_id);
}

/*
 * Change the switch's generation ID, blocking the port
 */
void
pipeline_bvs_table_port_block_block(uint32_t port)
{
    AIM_TRUE_OR_DIE(port < PORT_BLOCK_TABLE_SIZE);
    struct port_block_entry *entry = &port_block_entries[port];
    uint32_t lo = entry->switch_generation_id;
    uint32_t hi = entry->switch_generation_id >> 32;
    lo++;
    hi = murmur_round(hi, port);
    entry->switch_generation_id = (((uint64_t)hi) << 32) | lo;
    ind_ovs_port_set_generation_id(port, entry->switch_generation_id);
    AIM_LOG_INFO("Blocking port %u, switch generation id 0x%"PRIx64, port, entry->switch_generation_id);
}

uint64_t
pipeline_bvs_table_port_block_get_switch_generation_id(uint32_t port)
{
    AIM_TRUE_OR_DIE(port < PORT_BLOCK_TABLE_SIZE);
    struct port_block_entry *entry = &port_block_entries[port];
    return entry->switch_generation_id;
}

bool
pipeline_bvs_table_port_block_get_inuse(uint32_t port)
{
    AIM_TRUE_OR_DIE(port < PORT_BLOCK_TABLE_SIZE);
    struct port_block_entry *entry = &port_block_entries[port];
    return entry->inuse;
}
