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

/*
 * Longest Prefix Match trie implementation.
 *
 * This datastructure supports matching a 64 bit destination ipv6 address
 * network prefix against a cidr route and match to determine the possible
 * next hop in the network.
 * The most specific of the matching entries with the highest subnet mask
 * is called the longest prefix match. It is called this because it is also
 * the entry where the largest number of leading address bits of the
 * destination address match those in the entry.
 *
 * The actual datastructure used to store the cidr route entries and the
 * associated next hop is a trie.
 *
 * Refer modules/lpm/module/inc/lpm/lpm.h for more details.
 */

#ifndef LPM64_H
#define LPM64_H

#include <stdint.h>
#include <stdbool.h>

struct lpm64_trie;

/*
 * Create a lpm64 trie.
 */
struct lpm64_trie *lpm64_trie_create(void);

/*
 * Destroy a lpm64 trie.
 *
 * All entries should have been removed.
 */
void lpm64_trie_destroy(struct lpm64_trie *lpm64_trie);

/*
 * Functions for inserting nodes, removing nodes, and searching in
 * a lpm64 trie designed for IPv6 network prefix and netmasks.
 */

/*
 * lpm64 trie insert.
 *
 * Add a entry to the trie
 * @param lpm64_trie top level trie object containing the root info
 * @param key the key to add
 * @param key_mask_len the prefix associated with the key
 * @param value the value to add
 * @return 0 on success and -1 on failure
 */
int lpm64_trie_insert(struct lpm64_trie *lpm64_trie, uint64_t key,
                      uint8_t key_mask_len, void *value);

/*
 * Remove an entry from a lpm64 trie.
 *
 * @param lpm64_trie top level trie object containing the root info
 * @param key the key to remove
 * @param key_mask_len the prefix associated with the key
 */
void lpm64_trie_remove(struct lpm64_trie *lpm64_trie, uint64_t key,
                       uint8_t key_mask_len);

/*
 * Find an entry given a key in a lpm64 trie and return the data
 * associated with the longest prefix match.
 *
 * @param lpm64_trie top level trie object containing the root info
 * @param key the key to search for a longest prefix match
 * @return the value associated with the longest prefix match if found else null
 */
void *lpm64_trie_search(struct lpm64_trie *lpm64_trie, uint64_t key);

/*
 * Find if an lpm64 trie is empty or not.
 *
 * @param lpm64_trie top level trie object containing the root info
 * @return true if lpm64 trie is empty else return false
 */
bool lpm64_trie_is_empty(struct lpm64_trie *lpm64_trie);

#endif /* LPM64_H */
