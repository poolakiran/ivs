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

#ifndef TABLE_FSPAN_VLAN_H
#define TABLE_FSPAN_VLAN_H

void pipeline_bvs_table_fspan_vlan_register(void);
void pipeline_bvs_table_fspan_vlan_unregister(void);

extern uint16_t pipeline_bvs_fspan_vlan_vid;
extern uint16_t pipeline_bvs_fspan_vlan_vid_mask;

#endif
