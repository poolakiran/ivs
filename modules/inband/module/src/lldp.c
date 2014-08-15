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
inband_lldp_init(void)
{
    debug_counter_register(&invalid_tlv, "inband.invalid_tlv",
                           "Found an invalid LLDP TLV");
}
