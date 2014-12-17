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

static indigo_core_gentable_t *ecmp_table;
static const indigo_core_gentable_ops_t ecmp_ops;
uint16_t pipeline_bvs_table_ecmp_id;

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct ecmp_key *key)
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
            AIM_LOG_ERROR("ECMP name too long");
            return INDIGO_ERROR_PARAM;
        }
        if (strnlen((char *)name.data, name.bytes) != name.bytes) {
            AIM_LOG_ERROR("ECMP name includes null bytes");
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
parse_value(of_list_bsn_tlv_t *tlvs, struct ecmp_value *value)
{
    struct xbuf buckets_xbuf;
    xbuf_init(&buckets_xbuf);
    value->num_buckets = 0;

    of_object_t tlv;
    int rv;
    OF_LIST_BSN_TLV_ITER(tlvs, &tlv, rv) {
        if (tlv.object_id != OF_BSN_TLV_BUCKET) {
            AIM_LOG_ERROR("Unexpected tlv %s in ECMP group", of_class_name(&tlv));
            goto error;
        }

        struct ecmp_bucket *bucket =
            xbuf_reserve(&buckets_xbuf, sizeof(*bucket));

        of_list_bsn_tlv_t bucket_tlvs;
        of_bsn_tlv_bucket_value_bind(&tlv, &bucket_tlvs);

        if (pipeline_bvs_parse_gentable_next_hop(&bucket_tlvs, &bucket->next_hop) < 0) {
            AIM_LOG_ERROR("Failed to parse next-hop in ECMP group");
            goto error;
        }

        value->num_buckets++;

        if (bucket->next_hop.type != NEXT_HOP_TYPE_LAG) {
            AIM_LOG_ERROR("Invalid ECMP group next-hop type");
            goto error;
        }
    }

    xbuf_compact(&buckets_xbuf);
    value->buckets = xbuf_steal(&buckets_xbuf);

    return INDIGO_ERROR_NONE;

error:
    {
        int i;
        struct ecmp_bucket *buckets = xbuf_data(&buckets_xbuf);
        for (i = 0; i < value->num_buckets; i++) {
            pipeline_bvs_cleanup_next_hop(&buckets[i].next_hop);
        }
    }

    xbuf_cleanup(&buckets_xbuf);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct ecmp_value *value)
{
    int i;
    for (i = 0; i < value->num_buckets; i++) {
        pipeline_bvs_cleanup_next_hop(&value->buckets[i].next_hop);
    }
    aim_free(value->buckets);
}

static indigo_error_t
ecmp_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    struct ecmp_group ecmp;

    ecmp.id = OF_GROUP_ANY;

    if ((rv = parse_key(key, &ecmp.key)) < 0) {
        return rv;
    }

    if ((rv = parse_value(value, &ecmp.value)) < 0) {
        return rv;
    }

    *entry_priv = aim_memdup(&ecmp, sizeof(ecmp));

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ecmp_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    struct ecmp_value new_value;
    struct ecmp_group *ecmp = entry_priv;

    if ((rv = parse_value(value, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&ecmp->value);
    ecmp->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
ecmp_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct ecmp_group *ecmp = entry_priv;
    cleanup_value(&ecmp->value);
    aim_free(ecmp);
    return INDIGO_ERROR_NONE;
}

static void
ecmp_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* Nothing to do here */
}

static const indigo_core_gentable_ops_t ecmp_ops = {
    .add2 = ecmp_add,
    .modify2 = ecmp_modify,
    .del2 = ecmp_delete,
    .get_stats = ecmp_get_stats,
};

void
pipeline_bvs_table_ecmp_register(void)
{
    indigo_core_gentable_register("ecmp", &ecmp_ops, NULL, 128, 128,
                                  &ecmp_table);
    pipeline_bvs_table_ecmp_id = indigo_core_gentable_id(ecmp_table);
}

void
pipeline_bvs_table_ecmp_unregister(void)
{
    indigo_core_gentable_unregister(ecmp_table);
}

/* Caller must handle NULL return value in case of an empty group */
struct ecmp_bucket *
pipeline_bvs_table_ecmp_select(struct ecmp_group *ecmp, uint32_t hash)
{
    AIM_ASSERT(ecmp != NULL);

    if (ecmp->value.num_buckets == 0) {
        return NULL;
    }

    return &ecmp->value.buckets[hash % ecmp->value.num_buckets];
}

struct ecmp_group *
pipeline_bvs_table_ecmp_acquire(of_object_t *key)
{
    return indigo_core_gentable_acquire(ecmp_table, key);
}

void
pipeline_bvs_table_ecmp_release(struct ecmp_group *ecmp)
{
    if (ecmp->id != OF_GROUP_ANY) {
        indigo_core_group_release(ecmp->id);
    } else {
        /* HACK */
        of_object_t *key = of_bsn_tlv_name_new(OF_VERSION_1_3);
        of_octets_t name = { .data = (uint8_t *)ecmp->key.name, .bytes = strlen(ecmp->key.name) };
        if (of_bsn_tlv_name_value_set(key, &name) < 0) {
            AIM_DIE("Unexpected error creating ECMP key in pipeline_bvs_table_ecmp_release");
        }
        indigo_core_gentable_release(ecmp_table, key);
        of_object_delete(key);
    }
}

struct ecmp_group *
pipeline_bvs_table_ecmp_lookup(of_object_t *key)
{
    return indigo_core_gentable_lookup(ecmp_table, key);
}
