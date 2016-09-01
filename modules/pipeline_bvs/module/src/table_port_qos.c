/****************************************************************
 *
 *        Copyright 2016, Big Switch Networks, Inc.
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

#define TEMPLATE_NAME port_qos_hashtable
#define TEMPLATE_OBJ_TYPE struct port_qos_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static void cleanup_value(struct port_qos_value *value);

static indigo_core_gentable_t *port_qos_table;
static const indigo_core_gentable_ops_t port_qos_ops;
static bighash_table_t *port_qos_hashtable;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct port_qos_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected port key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_PORT) {
        of_bsn_tlv_port_value_get(&tlv, &key->port);
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
parse_value(of_list_bsn_tlv_t *tlvs, struct port_qos_value *value)
{
    value->dscp_profile = NULL;
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected gentable value TLV, instead got end of list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_VFP_CLASS_ID) {
        /* ignore */
    } else {
        AIM_LOG_ERROR("expected vfp_class_id value TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected reference TLV, instead got end of list");
        goto error;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t key;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &key);
        if (table_id == pipeline_bvs_table_priority_to_pcp_profile_id) {
            value->priority_to_pcp_profile = pipeline_bvs_table_priority_to_pcp_profile_acquire(&key);
            if (value->priority_to_pcp_profile == NULL) {
                AIM_LOG_ERROR("Nonexistent priority_to_pcp_profile in port_qos");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in port_qos");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference value TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        /* DSCP reference is optional */
        return INDIGO_ERROR_NONE;
    }

    if (tlv.object_id == OF_BSN_TLV_REFERENCE) {
        of_object_t key;
        uint16_t table_id;
        of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
        of_bsn_tlv_reference_key_bind(&tlv, &key);
        if (table_id == pipeline_bvs_table_dscp_to_priority_profile_id) {
            value->dscp_profile = pipeline_bvs_table_dscp_to_priority_profile_acquire(&key);
            if (value->dscp_profile == NULL) {
                AIM_LOG_ERROR("Nonexistent dscp_profile in port_qos");
                goto error;
            }
        } else {
            AIM_LOG_ERROR("unsupported gentable reference in port_qos");
            goto error;
        }
    } else {
        AIM_LOG_ERROR("expected reference value TLV, instead got %s", of_class_name(&tlv));
        goto error;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value TLV list, instead got %s", of_class_name(&tlv));
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct port_qos_value *value)
{
    if (value->dscp_profile) {
        pipeline_bvs_table_dscp_to_priority_profile_release(value->dscp_profile);
        value->dscp_profile = NULL;
    }

    if (value->priority_to_pcp_profile) {
        pipeline_bvs_table_priority_to_pcp_profile_release(value->priority_to_pcp_profile);
        value->priority_to_pcp_profile = NULL;
    }
}

static indigo_error_t
port_qos_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct port_qos_entry *entry = aim_zmalloc(sizeof(*entry));

    if ((rv = parse_key(key, &entry->key)) < 0) {
        aim_free(entry);
        return rv;
    }

    if ((rv = parse_value(value, &entry->value)) < 0) {
        aim_free(entry);
        return rv;
    }

    port_qos_hashtable_insert(port_qos_hashtable, entry);

    *entry_priv = entry;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_qos_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    struct port_qos_value new_value;
    struct port_qos_entry *entry = entry_priv;

    if ((rv = parse_value(value, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_qos_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct port_qos_entry *entry = entry_priv;
    bighash_remove(port_qos_hashtable, &entry->hash_entry);
    cleanup_value(&entry->value);
    aim_free(entry);
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static void
port_qos_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t port_qos_ops = {
    .add2 = port_qos_add,
    .modify2 = port_qos_modify,
    .del2 = port_qos_delete,
    .get_stats = port_qos_get_stats,
};

void
pipeline_bvs_table_port_qos_register(void)
{
    port_qos_hashtable = bighash_table_create(BIGHASH_AUTOGROW);
    indigo_core_gentable_register("port_qos", &port_qos_ops, NULL, 128, 128,
                                  &port_qos_table);
}

void
pipeline_bvs_table_port_qos_unregister(void)
{
    indigo_core_gentable_unregister(port_qos_table);
}

struct port_qos_entry *
pipeline_bvs_table_port_qos_lookup(uint32_t port)
{
    struct port_qos_key key = { port };
    return port_qos_hashtable_first(port_qos_hashtable, &key);
}
