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

#ifndef __INBAND_INT_H__
#define __INBAND_INT_H__

#include <inband/inband.h>

struct sockaddr_storage;

void inband_logger_init(void);
void inband_logger_reset(void);
void inband_logger_add_target(const struct sockaddr_storage *saddr);

#endif /* __INBAND_INT_H__ */
