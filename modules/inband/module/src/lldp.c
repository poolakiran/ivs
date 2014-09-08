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
#include <debug_counter/debug_counter.h>
#include "inband_int.h"
#include "inband_log.h"
#include "lldp.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

static debug_counter_t invalid_tlv;

/*
 * Parse the LLDP TLV starting at *data_p. Returns true if parsing was
 * successful. *remain should be initialized with the number of bytes
 * available starting from *data_p. After each successful call this
 * function will update *data_p, *remain, and *tlv.
 */
bool
inband_lldp_parse_tlv(const uint8_t **data_p, int *remain, struct lldp_tlv *tlv)
{
    const uint8_t *data = *data_p;

    if (*remain < 2) {
        AIM_LOG_WARN("Not enough bytes remaining for an LLDP TLV");
        debug_counter_inc(&invalid_tlv);
        return false;
    }

    memset(tlv, 0, sizeof(*tlv));
    tlv->type = data[0] >> 1;
    int payload_length = ((data[0] & 1) << 8) | data[1];

    if (tlv->type == 0 && payload_length == 0) {
        /* End of LLDPDU */
        return false;
    }

    int total_length = payload_length + 2;
    if (total_length > *remain) {
        AIM_LOG_WARN("Invalid LLDP TLV length %d", total_length);
        debug_counter_inc(&invalid_tlv);
        return false;
    }

    tlv->payload = data + 2;
    tlv->payload_length = payload_length;

    if (tlv->type == 127) {
        if (payload_length < 4) {
            AIM_LOG_WARN("Not enough payload bytes for an LLDP organizational TLV");
            debug_counter_inc(&invalid_tlv);
            return false;
        }
        tlv->oui = (data[2] << 16) | (data[3] << 8) | data[4];
        tlv->subtype = data[5];
        tlv->payload += 4;
        tlv->payload_length -= 4;
    }

    *data_p += total_length;
    *remain -= total_length;
    AIM_ASSERT(*remain >= 0);

    return true;
}

void
inband_lldp_builder_init(struct lldp_builder *builder)
{
    xbuf_init(&builder->xbuf);

    /* Construct ethernet header */
    struct ethhdr *eth = xbuf_reserve(&builder->xbuf, sizeof(*eth));
    uint8_t lldp_dst_mac[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
    memcpy(eth->h_dest, lldp_dst_mac, ETH_ALEN);
    memset(eth->h_source, 0, ETH_ALEN);
    eth->h_proto = htons(0x88cc);
}

void
inband_lldp_append(struct lldp_builder *builder, uint8_t type, const void *data, int len)
{
    AIM_ASSERT(type < 128);
    AIM_ASSERT(len < 256); /* we don't support the full 511 bytes */
    uint8_t *v = xbuf_reserve(&builder->xbuf, len + 2);
    v[0] = type << 1;
    v[1] = len;
    memcpy(v+2, data, len);
}

void
inband_lldp_append_bsn(struct lldp_builder *builder, uint8_t subtype, const void *data, int len)
{
    AIM_ASSERT(len < (256 - 4)); /* we don't support the full 511 bytes */
    uint8_t *v = xbuf_reserve(&builder->xbuf, len + 2);
    v[0] = 127 << 1;
    v[1] = len;
    v[2] = 0;
    v[3] = 0x26;
    v[4] = 0xe1;
    v[5] = subtype;
    memcpy(v+6, data, len);
}

of_octets_t
inband_lldp_finish(struct lldp_builder *builder)
{
    inband_lldp_append(builder, 0, NULL, 0);

    of_octets_t octets;
    octets.bytes = xbuf_length(&builder->xbuf);
    octets.data = xbuf_steal(&builder->xbuf);
    return octets;
}

void
inband_lldp_init(void)
{
    debug_counter_register(&invalid_tlv, "inband.invalid_tlv",
                           "Found an invalid LLDP TLV");
}
