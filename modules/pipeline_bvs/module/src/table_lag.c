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
#include <indigo/of_state_manager.h>
#include "pipeline_bvs_int.h"

static indigo_core_gentable_t *lag_table;
static const indigo_core_gentable_ops_t lag_ops;
uint16_t pipeline_bvs_table_lag_id;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct lag_key *key)
{
    of_object_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("expected name key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.object_id == OF_BSN_TLV_NAME) {
        of_octets_t name;
        of_bsn_tlv_name_value_get(&tlv, &name);
        if (name.bytes >= sizeof(key->name)) {
            AIM_LOG_ERROR("LAG name too long");
            return INDIGO_ERROR_PARAM;
        }
        if (strnlen((char *)name.data, name.bytes) != name.bytes) {
            AIM_LOG_ERROR("LAG name includes null bytes");
            return INDIGO_ERROR_PARAM;
        }
        memcpy(key->name, name.data, name.bytes);
        key->name[name.bytes] = 0;
    } else {
        AIM_LOG_ERROR("expected name key TLV, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key TLV list, instead got %s", of_class_name(&tlv));
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct lag_value *value)
{
    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);
    value->num_buckets = 0;

    of_object_t tlv;
    int rv;
    OF_LIST_BSN_TLV_ITER(tlvs, &tlv, rv) {
        if (tlv.object_id == OF_BSN_TLV_PORT) {
            struct lag_bucket *bucket =
                xbuf_reserve(&buckets_xbuf, sizeof(*bucket));
            of_bsn_tlv_port_value_get(&tlv, &bucket->port_no);
            value->num_buckets++;
        } else if (tlv.object_id == OF_BSN_TLV_VXLAN_EGRESS_LAG) {
            /* Ignore */
        } else {
            AIM_LOG_ERROR("expected port value TLV, instead got %s", of_class_name(&tlv));
            goto error;
        }
    }

    xbuf_compact(&buckets_xbuf);
    value->buckets = xbuf_steal(&buckets_xbuf);

    return INDIGO_ERROR_NONE;

error:
    xbuf_cleanup(&buckets_xbuf);
    return INDIGO_ERROR_PARAM;
}

static void
cleanup_value(struct lag_value *value)
{
    aim_free(value->buckets);
}

static indigo_error_t
lag_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct lag_group lag;

    lag.id = OF_GROUP_ANY;

    if ((rv = parse_key(key, &lag.key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value, &lag.value)) < 0) {
        return rv;
    }

    *entry_priv = aim_memdup(&lag, sizeof(lag));

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lag_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    struct lag_value new_value;
    struct lag_group *lag = entry_priv;

    if ((rv = parse_value(value, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&lag->value);
    lag->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
lag_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct lag_group *lag = entry_priv;
    cleanup_value(&lag->value);
    aim_free(lag);
    return INDIGO_ERROR_NONE;
}

static void
lag_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t lag_ops = {
    .add2 = lag_add,
    .modify2 = lag_modify,
    .del2 = lag_delete,
    .get_stats = lag_get_stats,
};

void
pipeline_bvs_table_lag_register(void)
{
    indigo_core_gentable_register("lag", &lag_ops, NULL, 128, 128,
                                  &lag_table);
    pipeline_bvs_table_lag_id = indigo_core_gentable_id(lag_table);
}

void
pipeline_bvs_table_lag_unregister(void)
{
    indigo_core_gentable_unregister(lag_table);
}

/* Caller must handle NULL return value in case of an empty group */
struct lag_bucket *
pipeline_bvs_table_lag_select(struct lag_group *lag, uint32_t hash)
{
    AIM_ASSERT(lag != NULL);

    /* Starting at a bucket chosen by 'hash', cycle through all buckets and
     * return the first one with a running port */
    int i;
    for (i = 0; i < lag->value.num_buckets; i++) {
        struct lag_bucket *b = &lag->value.buckets[(hash + i) % lag->value.num_buckets];
        if (!ind_ovs_port_running(b->port_no)) {
            packet_trace("skipping down port %u", b->port_no);
            continue;
        }
        if (!pipeline_bvs_table_port_block_check(b->port_no)) {
            packet_trace("skipping blocked port %u", b->port_no);
            continue;
        }
        return b;
    }

    return NULL;
}

struct lag_group *
pipeline_bvs_table_lag_acquire(of_object_t *key)
{
    return indigo_core_gentable_acquire(lag_table, key);
}

void
pipeline_bvs_table_lag_release(struct lag_group *lag)
{
    if (lag->id != OF_GROUP_ANY) {
        indigo_core_group_release(lag->id);
    } else {
        /* HACK */
        of_object_t *key = of_bsn_tlv_name_new(OF_VERSION_1_3);
        of_octets_t name = { .data = (uint8_t *)lag->key.name, .bytes = strlen(lag->key.name) };
        if (of_bsn_tlv_name_value_set(key, &name) < 0) {
            AIM_DIE("Unexpected error creating LAG key in pipeline_bvs_table_lag_release");
        }
        indigo_core_gentable_release(lag_table, key);
        of_object_delete(key);
    }
}

struct lag_group *
pipeline_bvs_table_lag_lookup(of_object_t *key)
{
    return indigo_core_gentable_lookup(lag_table, key);
}
