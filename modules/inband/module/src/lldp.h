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
#include <xbuf/xbuf.h>
#include <loci/loci.h>

#define LLDP_TLV_MANAGEMENT_ADDRESS 8
#define LLDP_ADDRESS_FAMILY_IPV4 1
#define LLDP_ADDRESS_FAMILY_IPV6 2

#define LLDP_TLV_VENDOR 127
#define LLDP_BSN_OUI 0x26e1
#define LLDP_BSN_INBAND_CONTROLLER_ADDR 5
#define LLDP_BSN_SUBTYPE_SWITCH_TYPE 1

struct lldp_tlv {
    uint8_t type;
    uint32_t oui;
    uint8_t subtype;
    const uint8_t *payload;
    uint16_t payload_length;
};

bool inband_lldp_parse_tlv(const uint8_t **data_p, int *remain, struct lldp_tlv *tlv);
void inband_lldp_init(void);

struct lldp_builder {
    struct xbuf xbuf;
};

void inband_lldp_builder_init(struct lldp_builder *builder);
void inband_lldp_append(struct lldp_builder *builder, uint8_t type, const void *data, int len);
void inband_lldp_append_vendor(struct lldp_builder *builder, uint32_t oui, uint8_t subtype, const void *data, int len);
of_octets_t inband_lldp_finish(struct lldp_builder *builder);

#endif
