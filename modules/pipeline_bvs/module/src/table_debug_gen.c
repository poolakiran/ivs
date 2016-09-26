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
#include <linux/if_ether.h>

static indigo_core_gentable_t *debug_gen_table;
static const indigo_core_gentable_ops_t debug_gen_ops;
static struct tcam *debug_tcam;

static void cleanup_value(struct debug_gen_value *value);
static inline bool
is_priority_valid(uint32_t valid_bitmap)
{
    return (valid_bitmap & DEBUG_GEN_PRIORITY) != 0;
}

static inline void
set_priority_valid(uint32_t *valid_bitmap)
{
    *valid_bitmap |= DEBUG_GEN_PRIORITY;
}

static inline bool
is_in_port_valid(uint32_t valid_bitmap)
{
    return (valid_bitmap & DEBUG_GEN_IN_PORT) != 0;
}

static inline void
set_in_port_valid(uint32_t *valid_bitmap)
{
    *valid_bitmap |= DEBUG_GEN_IN_PORT;
}

/* checker */
#define DEBUG_GEN_ATTR(_name, _bitflag, _tlvname, _type, _defmask)      \
    static inline bool                                                  \
    is_##_name##_valid(uint32_t valid_bitmap)                           \
    { return (valid_bitmap & _bitflag) != 0; }
DEBUG_GEN_ATTRS
#undef DEBUG_GEN_ATTR

/* setter */
#define DEBUG_GEN_ATTR(_name, _bitflag, tlvname, _type, _defmask)       \
    static inline void                                                  \
    set_##_name##_valid(uint32_t *valid_bitmap)                         \
    { *valid_bitmap |= _bitflag; }
DEBUG_GEN_ATTRS
#undef DEBUG_GEN_ATTR

/* returns true if the next TLV after that pointed to by "iterator"
 * has the expected object id */
static bool
is_next_tlv_type(of_list_bsn_tlv_t *tlvs,
                 of_object_t *iterator,
                 of_object_id_t expected)
{
    of_object_t copy = *iterator;
    if (of_list_bsn_tlv_next(tlvs, &copy) == OF_ERROR_NONE) {
        return (copy.object_id == expected);
    } else {
        return false;
    }
}

static indigo_error_t
parse_key(of_list_bsn_tlv_t *tlvs, struct debug_gen_key *key,
          struct debug_gen_key *mask, uint16_t *priority)
{
    const int MAX_TLVS = 512;
    int count;
    of_object_t iter;
    bool done = false;
    uint32_t valid_bitmap = 0;

    if (of_list_bsn_tlv_first(tlvs, &iter) != OF_ERROR_NONE) {
        AIM_LOG_ERROR("expected a key TLV, instead got end of list");
        return INDIGO_ERROR_PARAM;
    }

    memset(key, 0, sizeof(*key));
    memset(mask, 0, sizeof(*mask));

    /* iterate over key tlvs:
     * convention for masked values: value must immediately precede mask */
    for (count = 0; !done && count < MAX_TLVS; count++) {
        switch (iter.object_id) {
        case OF_BSN_TLV_PRIORITY:
            {
                uint32_t prio;
                of_bsn_tlv_priority_value_get(&iter, &prio);
                if (!is_priority_valid(valid_bitmap)) {
                    *priority = prio;
                    set_priority_valid(&valid_bitmap);
                } else {
                    AIM_LOG_ERROR("Parsed priority %u but already set to %u", priority, prio);
                    return INDIGO_ERROR_PARAM;
                }
            }
            break;
        case OF_BSN_TLV_PORT:
            {
                of_port_no_t ofport;
                of_bsn_tlv_port_value_get(&iter, &ofport);

                if (!is_in_port_valid(valid_bitmap)) {
                    key->in_port = ofport;
                    mask->in_port = 0xffffffff;
                    set_in_port_valid(&valid_bitmap);
                } else {
                    AIM_LOG_ERROR("Parsed in_port %u but already set to %u", ofport, key->in_port);
                    return INDIGO_ERROR_PARAM;
                }
            }
            break;
#define DEBUG_GEN_ATTR(_name, _bitflag, _tlvname, _type, _defmask)      \
        case OF_BSN_TLV_##_tlvname:                                     \
            if (!is_##_name##_valid(valid_bitmap)) {                    \
                of_bsn_tlv_##_name##_value_get(&iter, &key->_name);     \
                mask->_name = _defmask;                                 \
                if (is_next_tlv_type(tlvs, &iter, OF_BSN_TLV_##_tlvname)) { \
                    of_list_bsn_tlv_next(tlvs, &iter);                  \
                    of_bsn_tlv_##_name##_value_get(&iter, &mask->_name);\
                }                                                       \
                set_##_name##_valid(&valid_bitmap);                     \
            } else {                                                    \
                AIM_LOG_ERROR("duplicate %s TLV",                       \
                              of_object_id_str[OF_BSN_TLV_##_tlvname]); \
                return INDIGO_ERROR_PARAM;                              \
            }                                                           \
            break;
DEBUG_GEN_ATTRS
#undef DEBUG_GEN_ATTR
        default:
            AIM_LOG_ERROR("debug key has unknown TLV %s",
                          of_class_name(&iter));
            return INDIGO_ERROR_PARAM;
        }
        if (of_list_bsn_tlv_next(tlvs, &iter) == OF_ERROR_RANGE) {
            done = true;
        }
    }
    if (count == MAX_TLVS) {
        AIM_LOG_ERROR("debug key TLV count exceeds max %d", MAX_TLVS);
        return INDIGO_ERROR_PARAM;
    }

    /* priority must be set */
    if (!is_priority_valid(valid_bitmap)) {
        AIM_LOG_ERROR("Required priority TLV not present in debug key");
        return INDIGO_ERROR_PARAM;
    }

    if (is_eth_type_valid(valid_bitmap)) {
        if (key->eth_type == ETH_P_IP) {
            if (is_ipv6_src_valid(valid_bitmap) || is_ipv6_dst_valid(valid_bitmap)) {
                AIM_LOG_ERROR("IPv6 fields set for IPv4 eth type");
                return INDIGO_ERROR_PARAM;
            }
        } else if (key->eth_type == ETH_P_IPV6) {
            if (is_ipv4_src_valid(valid_bitmap) || is_ipv4_dst_valid(valid_bitmap)) {
                AIM_LOG_ERROR("IPv4 fields set for IPv6 eth type");
                return INDIGO_ERROR_PARAM;
            }
        }
    } else if (is_ipv4_src_valid(valid_bitmap) || is_ipv4_dst_valid(valid_bitmap) ||
               is_ipv6_src_valid(valid_bitmap) || is_ipv6_dst_valid(valid_bitmap)) {
        AIM_LOG_ERROR("src/dest address(es) set but eth type not specified");
        return INDIGO_ERROR_PARAM;
    }

    if (is_ip_proto_valid(valid_bitmap)) {
        if (key->ip_proto == IPPROTO_TCP) {
            if (is_udp_src_valid(valid_bitmap) || is_udp_dst_valid(valid_bitmap)) {
                AIM_LOG_ERROR("UDP src/dst ports set for "
                              "TCP protocol");
                return INDIGO_ERROR_PARAM;
            }
        } else if (key->ip_proto == IPPROTO_UDP) {
            if (is_tcp_src_valid(valid_bitmap) || is_tcp_dst_valid(valid_bitmap)) {
                AIM_LOG_ERROR("TCP src/dst ports set for "
                              "UDP protocol");
                return INDIGO_ERROR_PARAM;
            }
        } else if (is_tcp_src_valid(valid_bitmap) || is_tcp_dst_valid(valid_bitmap) ||
                   is_udp_src_valid(valid_bitmap) || is_udp_dst_valid(valid_bitmap)) {
            AIM_LOG_ERROR("L4 fields set for unhandled IP proto %u",
                          key->ip_proto);
            return INDIGO_ERROR_PARAM;
        }
    } else if (is_tcp_src_valid(valid_bitmap) || is_tcp_dst_valid(valid_bitmap) ||
               is_udp_src_valid(valid_bitmap) || is_udp_dst_valid(valid_bitmap)) {
        AIM_LOG_ERROR("L4 fields set but IP proto is not set");
        return INDIGO_ERROR_PARAM;
    }

    if (is_ip_proto_valid(valid_bitmap) ||
        is_dscp_valid(valid_bitmap) || is_ecn_valid(valid_bitmap) ||
        is_tcp_src_valid(valid_bitmap) || is_tcp_dst_valid(valid_bitmap) ||
        is_udp_src_valid(valid_bitmap) || is_udp_dst_valid(valid_bitmap)) {
        key->ip_pkt = 1;
        mask->ip_pkt = 0xff;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
parse_value(of_list_bsn_tlv_t *tlvs, struct debug_gen_value *value)
{
    const int MAX_TLVS = 4;
    int count;
    of_object_t tlv;
    bool done = false;
    of_port_no_t port;
    uint16_t table_id;
    of_object_t refkey;

    value->span = NULL;
    value->lag = NULL;
    value->drop = false;
    value->cpu = false;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_TRACE("end of value TLV list, skipping value parsing");
        return INDIGO_ERROR_NONE;
    }

    for (count = 0; !done && count < MAX_TLVS; count++) {
        switch (tlv.object_id) {
        case OF_BSN_TLV_PORT:
            of_bsn_tlv_port_value_get(&tlv, &port);
            if (port != OF_PORT_DEST_CONTROLLER) {
                AIM_LOG_ERROR("Unexpected output port %u in debug_gen_table", port);
                goto error;
            }
            value->cpu = true;
            break;
        case OF_BSN_TLV_DROP:
            value->drop = true;
            break;
        case OF_BSN_TLV_REFERENCE:
            of_bsn_tlv_reference_table_id_get(&tlv, &table_id);
            of_bsn_tlv_reference_key_bind(&tlv, &refkey);
            if (table_id == pipeline_bvs_table_span_id) {
                if (value->span != NULL) {
                    AIM_LOG_ERROR("Duplicate SPAN action in debug gen table");
                    goto error;
                }
                value->span = pipeline_bvs_table_span_acquire(&refkey);
                if (value->span == NULL) {
                    AIM_LOG_ERROR("Nonexistent SPAN in debug gen table");
                    goto error;
                }
            } else if (table_id == pipeline_bvs_table_lag_id) {
                if (value->lag != NULL) {
                    AIM_LOG_ERROR("Duplicate LAG action in debug gen table");
                    goto error;
                }
                value->lag = pipeline_bvs_table_lag_acquire(&refkey);
                if (value->lag == NULL) {
                    AIM_LOG_ERROR("Nonexistent LAG in debug gen table");
                    goto error;
                }
            } else {
                AIM_LOG_ERROR("Unsupported gentable reference in debug gen gentable");
                goto error;
            }
            break;
        default:
            AIM_LOG_ERROR("debug value has unknown TLV %s", of_class_name(&tlv));
            goto error;
        }

        if (of_list_bsn_tlv_next(tlvs, &tlv) == OF_ERROR_RANGE) {
            done = true;
        }
    }

    if (count == MAX_TLVS) {
        AIM_LOG_ERROR("debug gen table value TLV count exceeds max %d", MAX_TLVS);
        goto error;
    }

    return INDIGO_ERROR_NONE;

error:
    cleanup_value(value);
    return INDIGO_ERROR_BAD_ACTION;
}

static void
cleanup_value(struct debug_gen_value *value)
{
    if (value->span != NULL) {
        pipeline_bvs_table_span_release(value->span);
    }

    if (value->lag != NULL) {
        pipeline_bvs_table_lag_release(value->lag);
    }
}

static indigo_error_t
debug_gen_add(indigo_cxn_id_t cxn_id, void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct debug_gen_entry *entry = aim_zmalloc(sizeof(*entry));
    struct debug_gen_key key;
    struct debug_gen_key mask;
    uint16_t priority;

    if ((rv = parse_key(key_tlvs, &key, &mask, &priority)) < 0) {
        aim_free(entry);
        return rv;
    }

    if ((rv = parse_value(value_tlvs, &entry->value)) < 0) {
        aim_free(entry);
        return rv;
    }

    AIM_LOG_VERBOSE("Create debug gen entry prio=%u in_port=%u ingress_port_group_id=%u/%#x "
                    "eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} "
                    "eth_type=%#x/%#x vlan_vid=%u/%#x "
                    "vrf=%u/%#x l3_src_class_id=%u/%#x "
                    "ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} "
                    "ipv6_src=%{ipv6a}/%{ipv6a} ipv6_dst=%{ipv6a}/%{ipv6a} "
                    "ip_proto=%u/%#x dscp=%#x/%#x ecn=%#x/%#x "
                    "tcp_src=%u/%#x tcp_dst=%u/%#x udp_src=%u/%#x udp_dst=%u/%#x "
                    "-> span=%s lag=%s cpu=%d drop=%d",
                    priority, key.in_port, key.ingress_port_group_id, mask.ingress_port_group_id,
                    &key.eth_src, &mask.eth_src, &key.eth_dst, &mask.eth_dst,
                    key.eth_type, mask.eth_type, key.vlan_vid, mask.vlan_vid,
                    key.vrf, mask.vrf, key.l3_src_class_id, mask.l3_src_class_id,
                    key.ipv4_src, mask.ipv4_src, key.ipv4_dst, mask.ipv4_dst,
                    &key.ipv6_src, &mask.ipv6_src, &key.ipv6_dst, &mask.ipv6_dst,
                    key.ip_proto, mask.ip_proto, key.dscp, mask.dscp, key.ecn, mask.ecn,
                    key.tcp_src, mask.tcp_src, key.tcp_dst, mask.tcp_dst,
                    key.udp_src, mask.udp_src, key.udp_dst, mask.udp_dst,
                    span_name(entry->value.span), lag_name(entry->value.lag),
                    entry->value.cpu, entry->value.drop);

    stats_alloc(&entry->stats_handle);

    tcam_insert(debug_tcam, &entry->tcam_entry, &key, &mask, priority);

    *entry_priv = entry;
    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
debug_gen_modify(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct debug_gen_value new_value;
    struct debug_gen_entry *entry = entry_priv;

    if ((rv = parse_value(value_tlvs, &new_value)) < 0) {
        return rv;
    }

    cleanup_value(&entry->value);
    entry->value = new_value;

    ind_ovs_barrier_defer_revalidation(cxn_id);
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
debug_gen_delete(indigo_cxn_id_t cxn_id, void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct debug_gen_entry *entry = entry_priv;

    tcam_remove(debug_tcam, &entry->tcam_entry);

    ind_ovs_barrier_defer_revalidation(cxn_id);
    cleanup_value(&entry->value);
    stats_free(&entry->stats_handle);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static void
debug_gen_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *stats)
{
    struct debug_gen_entry *entry = entry_priv;
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

static const indigo_core_gentable_ops_t debug_gen_ops = {
    .add2 = debug_gen_add,
    .modify2 = debug_gen_modify,
    .del2 = debug_gen_delete,
    .get_stats = debug_gen_get_stats,
};

void
pipeline_bvs_table_debug_gen_register(void)
{
    debug_tcam = tcam_create(sizeof(struct debug_gen_key), ind_ovs_salt);
    indigo_core_gentable_register("debug", &debug_gen_ops, NULL, 128, 128,
                                  &debug_gen_table);
}

void
pipeline_bvs_table_debug_gen_unregister(void)
{
    indigo_core_gentable_unregister(debug_gen_table);
    tcam_destroy(debug_tcam);
}

struct debug_gen_entry *
pipeline_bvs_table_debug_gen_lookup(const struct debug_gen_key *key)
{
    struct tcam_entry *tcam_entry = tcam_match(debug_tcam, key);
    if (tcam_entry) {
        const struct debug_gen_key *entry_key = tcam_entry->key;
        const struct debug_gen_key *entry_mask = tcam_entry->mask;
        struct debug_gen_entry *entry = container_of(tcam_entry, tcam_entry, struct debug_gen_entry);
        packet_trace("Hit debug gen entry prio=%u in_port=%u/%#x ingress_port_group_id=%u/%#x "
                     "eth_src=%{mac}/%{mac} eth_dst=%{mac}/%{mac} "
                     "eth_type=%#x/%#x vlan_vid=%u/%#x "
                     "vrf=%u/%#x l3_src_class_id=%u/%#x "
                     "ipv4_src=%{ipv4a}/%{ipv4a} ipv4_dst=%{ipv4a}/%{ipv4a} "
                     "ipv6_src=%{ipv6a}/%{ipv6a} ipv6_dst=%{ipv6a}/%{ipv6a} "
                     "ip_proto=%u/%#x dscp=%#x/%#x ecn=%#x/%#x "
                     "tcp_src=%u/%#x tcp_dst=%u/%#x udp_src=%u/%#x udp_dst=%u/%#x "
                     "-> span=%s lag=%s cpu=%d drop=%d",
                     tcam_entry->priority, entry_key->in_port, entry_mask->in_port,
                     entry_key->ingress_port_group_id, entry_mask->ingress_port_group_id,
                     &entry_key->eth_src, &entry_mask->eth_src, &entry_key->eth_dst, &entry_mask->eth_dst,
                     entry_key->eth_type, entry_mask->eth_type, entry_key->vlan_vid, entry_mask->vlan_vid,
                     entry_key->vrf, entry_mask->vrf, entry_key->l3_src_class_id, entry_mask->l3_src_class_id,
                     entry_key->ipv4_src, entry_mask->ipv4_src, entry_key->ipv4_dst, entry_mask->ipv4_dst,
                     &entry_key->ipv6_src, &entry_mask->ipv6_src, &entry_key->ipv6_dst, &entry_mask->ipv6_dst,
                     entry_key->ip_proto, entry_mask->ip_proto, entry_key->dscp, entry_mask->dscp, entry_key->ecn, entry_mask->ecn,
                     entry_key->tcp_src, entry_mask->tcp_src, entry_key->tcp_dst, entry_mask->tcp_dst,
                     entry_key->udp_src, entry_mask->udp_src, entry_key->udp_dst, entry_mask->udp_dst,
                     span_name(entry->value.span), lag_name(entry->value.lag), entry->value.cpu, entry->value.drop);

        return entry;
    }

    packet_trace("Miss debug gen entry in_port=%d ingress_port_group_id=%u eth_src=%{mac} eth_dst=%{mac} "
                 "eth_type=%#x vlan_vid=%u vrf=%u l3_src_class_id=%u "
                 "ipv4_src=%{ipv4a} ipv4_dst=%{ipv4a} ipv6_src=%{ipv6a} ipv6_dst=%{ipv6a} "
                 "ip_proto=%u dscp=%#x ecn=%#x tcp_src=%u tcp_dst=%u udp_src=%u udp_dst=%u",
                 key->in_port, key->ingress_port_group_id, &key->eth_src, &key->eth_dst,
                 key->eth_type, key->vlan_vid, key->vrf, key->l3_src_class_id,
                 key->ipv4_src, key->ipv4_dst, &key->ipv6_src, &key->ipv6_dst,
                 key->ip_proto, key->dscp, key->ecn, key->tcp_src, key->tcp_dst, key->udp_src, key->udp_dst);
    return NULL;
}
