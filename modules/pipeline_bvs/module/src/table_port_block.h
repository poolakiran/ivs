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

#ifndef TABLE_PORT_BLOCK_H
#define TABLE_PORT_BLOCK_H

void pipeline_bvs_table_port_block_register(void);
void pipeline_bvs_table_port_block_unregister(void);
bool pipeline_bvs_table_port_block_check(uint32_t port);
void pipeline_bvs_table_port_block_block(uint32_t port);
uint64_t pipeline_bvs_table_port_block_get_switch_generation_id(uint32_t port);
bool pipeline_bvs_table_port_block_get_inuse(uint32_t port);

#endif
