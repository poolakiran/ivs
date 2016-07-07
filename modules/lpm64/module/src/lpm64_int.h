/****************************************************************
 *
 *        Copyright 2016, Big Switch Networks, Inc.
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

#ifndef __LPM64_INT_H__
#define __LPM64_INT_H__

#include <lpm64/lpm64.h>
#include <slot_allocator/slot_allocator.h>

/*
 * Max entries limit per lpm64 trie is 16000. And since each entry creation
 * can lead to 2 slots being used, so 32000 slots are a sufficient upper
 * bound of 16000 entries.
 */
#define LPM64_TRIE_ENTRY_COUNT 32000

/*
 * Number of entries to allocate at creation. The trie will grow up to the
 * maximum size.
 */
#define LPM64_TRIE_INITIAL_ALLOCATION 2

/*
 * lpm64 trie entry.
 */
struct lpm64_trie_entry {
    uint64_t key;                     /* Node key        */
    uint8_t mask_len;                 /* Cidr of mask    */
    uint8_t match_bit_count;          /* Number of bits to match */
    uint32_t left;                    /* Slot number of left child */
    uint32_t right;                   /* Slot number of right child */
    void *value;                      /* Node value      */
};

/*
 * Top-level lpm64_trie object.
 */
struct lpm64_trie {
    struct slot_allocator *lpm64_trie_entry_allocator;
    struct lpm64_trie_entry *lpm64_trie_entries;
    uint32_t root;
    uint32_t size;
    uint32_t allocated;
};

#endif /* __LPM64_INT_H__ */
