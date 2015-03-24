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

#ifndef PKTIN_H
#define PKTIN_H

/* Overall minimum average interval between sflow, debug and acl packet-ins (in us) */
#define GLOBAL_PKTIN_INTERVAL 10000 /* 100 packets/sec */

/* Per-port minimum average interval between packet-ins (in us) */
#define PORT_PKTIN_INTERVAL 5000

/* Per-port packet-in burstiness tolerance. */
#define PKTIN_BURST 32

void pipeline_bvs_pktin_socket_register();
void pipeline_bvs_pktin_socket_unregister();
void pipeline_bvs_port_pktin_socket_register(of_port_no_t port_no);
void pipeline_bvs_port_pktin_socket_unregister(of_port_no_t port_no);

struct ind_ovs_pktin_socket *pipeline_bvs_get_pktin_socket(of_port_no_t port_no,
                                                           uint64_t userdata);

#endif
