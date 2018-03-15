/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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

#ifndef __OVSDRIVER_H__
#define __OVSDRIVER_H__

struct xbuf;

indigo_error_t ind_ovs_init(const char *datapath_name, bool hitless);
void ind_ovs_finish(void);
void ind_ovs_enable(void);

void ind_ovs_uplink_add(const char *name);
indigo_error_t ind_ovs_port_add_internal(const char *port_name);
void ind_ovs_kflow_trace_enabled_set(bool status);

#endif
