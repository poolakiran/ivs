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

#ifndef PIPELINE_BIGTAP_INT_H
#define PIPELINE_BIGTAP_INT_H

#include <stdbool.h>
#include <loci/loci.h>

#define MAX_PORTS 128

bool pipeline_bigtap_check_tcam_mask(const of_match_fields_t *_mask, const of_match_fields_t *_minimum, const of_match_fields_t *_maximum);

#endif
