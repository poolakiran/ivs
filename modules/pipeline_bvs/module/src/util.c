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

#include "pipeline_bvs_int.h"

/**
 * Check that 'mask' has all the bits set that are set in 'minimum' and
 * no more bits than are set in 'maximum'.
 *
 * TODO optimize by checking a word at a time
 */
bool
pipeline_bvs_check_tcam_mask(const of_match_fields_t *_mask,
                             const of_match_fields_t *_minimum,
                             const of_match_fields_t *_maximum)
{
    const uint8_t *mask = (const uint8_t *)_mask;
    const uint8_t *minimum = (const uint8_t *)_minimum;
    const uint8_t *maximum = (const uint8_t *)_maximum;

    int i;
    for (i = 0; i < sizeof(of_match_fields_t); i++) {
        if ((mask[i] & minimum[i]) != minimum[i]) {
            return false;
        }
        if ((mask[i] & maximum[i]) != mask[i]) {
            return false;
        }
    }

    return true;
}
