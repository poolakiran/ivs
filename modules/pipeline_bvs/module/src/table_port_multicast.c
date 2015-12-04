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
#include "pipeline_bvs_int.h"

#define TEMPLATE_NAME port_multicast_hashtable
#define TEMPLATE_OBJ_TYPE struct port_multicast_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *port_multicast_table;
static const indigo_core_gentable_ops_t port_multicast_ops;
static bighash_table_t *port_multicast_hashtable;

static void cleanup_value(struct port_multicast_value *value);

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct port_multicast_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected port key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_PORT) {
        of_bsn_tlv_port_value_get(&tlv, &key->port_no);
    } else {
        AIM_LOG_ERROR("expected port key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct port_multicast_value *value)
{
    of_object_t tlv;
    memset(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        goto end;
    }

    if (tlv.object_id == OF_BSN_TLV_IGMP_SNOOPING) {
        value->igmp_snooping = true;
        if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
            goto end;
        }
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

end:
    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct port_multicast_value *value)
{
}

static indigo_error_t
port_multicast_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct port_multicast_key key;
    struct port_multicast_value value;

    if ((rv = parse_key(key_tlvs, &key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &value)) < 0) {
        return rv;
    }

    struct port_multicast_entry *entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;

    port_multicast_hashtable_insert(port_multicast_hashtable, entry);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_multicast_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct port_multicast_value new_value;
    struct port_multicast_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_multicast_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct port_multicast_entry *entry = entry_priv;
    bighash_remove(port_multicast_hashtable, &entry->hash_entry);
    cleanup_value(&entry->value);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
port_multicast_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t port_multicast_ops = {
    .add2 = port_multicast_add,
    .modify2 = port_multicast_modify,
    .del2 = port_multicast_delete,
    .get_stats = port_multicast_get_stats,
};

void
pipeline_bvs_table_port_multicast_register(void)
{
    port_multicast_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_gentable_register("port_multicast", &port_multicast_ops, NULL, 128, 128,
                                  &port_multicast_table);
}

void
pipeline_bvs_table_port_multicast_unregister(void)
{
    indigo_core_gentable_unregister(port_multicast_table);
    bighash_table_destroy(port_multicast_hashtable, NULL);
}

struct port_multicast_entry *
pipeline_bvs_table_port_multicast_lookup(uint32_t port_no)
{
    struct port_multicast_key key = { .port_no = port_no };
    struct port_multicast_entry *entry =
        port_multicast_hashtable_first(port_multicast_hashtable, &key);
    if (entry) {
        packet_trace("Hit port_multicast entry port_no=%u -> igmp_snooping=%u",
                     entry->key.port_no, entry->value.igmp_snooping);
    } else {
        packet_trace("Miss port_multicast entry port_no=%u", port_no);
    }
    return entry;
}
