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

#ifndef __INBAND_LLDP_H__
#define __INBAND_LLDP_H__

#include <stdint.h>
#include <stdbool.h>

#define LLDP_TLV_MANAGEMENT_ADDRESS 8
#define LLDP_ADDRESS_FAMILY_IPV4 1
#define LLDP_ADDRESS_FAMILY_IPV6 2

struct lldp_tlv {
    uint8_t type;
    uint32_t oui;
    uint8_t subtype;
    const uint8_t *payload;
    uint16_t payload_length;
};

bool inband_lldp_parse_tlv(const uint8_t **data_p, int *remain, struct lldp_tlv *tlv);
void inband_lldp_init(void);

#endif
