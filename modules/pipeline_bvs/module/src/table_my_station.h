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

#ifndef TABLE_MY_STATION_H
#define TABLE_MY_STATION_H

struct my_station_key {
    of_mac_addr_t mac;
    uint16_t pad;
};
AIM_STATIC_ASSERT(MY_STATION_KEY_SIZE, sizeof(struct my_station_key) == 8);

struct my_station_entry {
    struct tcam_entry tcam_entry;
};

void pipeline_bvs_table_my_station_register(void);
void pipeline_bvs_table_my_station_unregister(void);
struct my_station_entry *pipeline_bvs_table_my_station_lookup(const uint8_t *mac);

#endif
