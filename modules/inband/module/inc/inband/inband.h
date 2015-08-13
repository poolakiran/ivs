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

#ifndef INBAND_H
#define INBAND_H

#include <indigo/of_state_manager.h>
#include <PPE/ppe.h>

void inband_init(void);
void inband_receive_packet(uint8_t *data, unsigned int len, of_port_no_t in_port);
void inband_send_lldp(of_port_no_t port_no);
void inband_log(aim_log_flag_t flag, const char *str);

#endif /* INBAND_H */
