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

/*
 * Longest Prefix Match trie implementation.
 *
 * This datastructure supports matching a 32 bit destination ip address against
 * a cidr route and match to determine the possible next hop in the network.
 * The most specific of the matching entries with the highest subnet mask
 * is called the longest prefix match. It is called this because it is also
 * the entry where the largest number of leading address bits of the
 * destination address match those in the entry.
 *
 * The actual datastructure used to store the cidr route entries and the
 * associated next hop is a trie.
 */

/* The best way to understand the Trie structure is to use an example and a
 * diagram.
 * Assume that the following entries are present in the trie:
 * 192.168.0.0/16 with value A
 * 192.168.2.0/24 with value B
 * 192.168.3.0/24 with value C
 * 10.0.0.0/8 with value D
 * 10.1.1.0/24 with value E
 * The trie structure will look like this
 * ________________
 * |key=192.168.0.0|
 * |maskLen=8 OR 16|
 * |matchBitCount=0|
 * |value=null     |
 * -------------------------
 *   |Left=1                |Right=0
 * __|_______________     __|_______________
 * |key=192.168.0.0 |     |key=10.0.0.0    |
 * |maskLen=16      |     |maskLen=8       |
 * |matchBitCount=16|     |matchBitCount=8 |
 * |value=A         |     |value=D         |
 * -----------------      -----------------
 *  |Left=1   |Right=0       |Left=1    |Right=0
 * null ______|________     null      ___|_____________
 *     |key=192.168.2.0|             |key=10.1.1.0     |
 *     |maskLen=24     |             |maskLen=24       |
 *     |matchBitCount=7|             |matchBitCount=16 |
 *     |value=null     |             |value=E          |
 *     ----------------              ------------------|
 *      Left=1     |Right=0          |Left=1     |Right=0
 *      |               |           null        null
 * _____|____________ __|______________
 * |key=192.168.3.0 | |key=192.168.2.0 |
 * |maskLen=24      | |maskLen=24      |
 * |matchBitCount=1 | |matchBitCount=1 |
 * |value=C         | |value=B         |
 * -----------------  ------------------
 *  |Left=1  |Right=0   |Left=1  |Right=0
 * null     null      null      null
 *
 * It can be seen that the maskLen always indicates the total maskLen in the key
 * The important value is matchBitCount which indicates the number of bits that
 * can be considered for a match at each level. This count is aggregated from
 * the root node. For eg. in order to search the trie, starting from the MSB, at
 * the root node we match '0' bits. If the first bit of the query is 0, then we
 * match on the right subtree. At this point, we will match the first 8 bits.
 * If the value was say 10.1.1.1, then we would have further matches. At the
 * third level, we would match bits 9 to 24 (starting from MSB) and so on.
 * The matchBitCount value indicates the number of bits that can be matched
 * at this node. The start offset of the bit is the aggregate of the number of
 * bits that have been matched from the root till this node.
 */

#ifndef LPM_H
#define LPM_H

#include <stdint.h>
#include <stdbool.h>

struct lpm_trie;

/*
 * Create a lpm trie.
 */
struct lpm_trie *lpm_trie_create(void);

/*
 * Destroy a lpm trie.
 *
 * All entries should have been removed.
 */
void lpm_trie_destroy(struct lpm_trie *lpm_trie);

/*
 * Functions for inserting nodes, removing nodes, and searching in
 * a lpm trie designed for IP addresses and netmasks.
 */

/*
 * lpm trie insert.
 *
 * Add a entry to the trie
 * @param lpm_trie top level trie object containing the root info
 * @param key the key to add
 * @param key_mask_len the prefix associated with the key
 * @param value the value to add
 */
void lpm_trie_insert(struct lpm_trie *lpm_trie, uint32_t key,
                     uint8_t key_mask_len, void *value);

/*
 * Remove an entry from a lpm trie.
 *
 * @param lpm_trie top level trie object containing the root info
 * @param key the key to remove
 * @param key_mask_len the prefix associated with the key
 */
void lpm_trie_remove(struct lpm_trie *lpm_trie, uint32_t key,
                     uint8_t key_mask_len);

/*
 * Find an entry given a key in a lpm trie and return the data
 * associated with the longest prefix match.
 *
 * @param lpm_trie top level trie object containing the root info
 * @param key the key to search for a longest prefix match
 * @return the value associated with the longest prefix match if found else null
 */
void *lpm_trie_search(struct lpm_trie *lpm_trie, uint32_t key);

/*
 * Find if an lpm trie is empty or not.
 *
 * @param lpm_trie top level trie object containing the root info
 * @return true if lpm trie is empty else return false
 */
bool lpm_trie_is_empty(struct lpm_trie *lpm_trie);

#endif /* LPM_H */
