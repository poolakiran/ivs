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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

/*
 * See the comments in lpm128.h for a high level description.
 */

#include <AIM/aim.h>
#include "lpm128_int.h"
#include "lpm128_log.h"
#include <inttypes.h>

static inline struct lpm128_trie_entry *
lpm128_trie_entry_object(struct lpm128_trie *lpm128_trie, uint32_t slot)
{
    AIM_ASSERT(slot != SLOT_INVALID, "invalid slot");

    return &((lpm128_trie)->lpm128_trie_entries[slot]);
}

/*
 * Private function used to return whether
 * or not bit 'i' counting from the MSB is set in 'key'.
 */
static bool
is_bit_set(uint64_t key, int i)
{
    return key & (1ULL << (63-i));
}

/*
 * Compute netmask address given prefix
 */
static uint64_t
netmask(int prefix)
{
    if (prefix) {
        return(~((1ULL << (64 - prefix)) - 1));
    }

    return 0;
}

/*
 * Round up to the next power of 2
 */
static uint32_t
roundup(uint32_t x)
{
    return 1 << aim_log2_u32(x);
}

/*
 * Create a lpm128 trie entry node
 */
static uint32_t
trie_entry_create(struct lpm128_trie *lpm128_trie, uint64_t key, uint8_t mask_len,
                  uint8_t bit, void *value, uint32_t left, uint32_t right)
{
    AIM_LOG_TRACE("Create lpm128 trie entry with ipv6 key=%"PRIx64"/%u, bit=%u",
                  key, mask_len, bit);

    uint32_t slot = slot_allocator_alloc(lpm128_trie->lpm128_trie_entry_allocator);
    AIM_ASSERT(slot != SLOT_INVALID, "Failed to create slot for lpm128 trie entry");

    if (slot >= lpm128_trie->allocated) {
        AIM_LOG_TRACE("Growing lpm128 trie to %d entries", lpm128_trie->allocated * 2);
        lpm128_trie->allocated = roundup(slot*2);
        AIM_ASSERT(lpm128_trie->allocated > slot, "LPM128 did not grow to contain new slot");
        lpm128_trie->lpm128_trie_entries =
            aim_realloc(lpm128_trie->lpm128_trie_entries, lpm128_trie->allocated * sizeof(struct lpm128_trie_entry));
    }

    struct lpm128_trie_entry *entry = lpm128_trie_entry_object(lpm128_trie, slot);

    entry->key = key;
    entry->mask_len = mask_len;
    entry->match_bit_count = bit;
    entry->value = value;
    entry->left = left;
    entry->right = right;

    return slot;
}

/*
 * Remove a lpm128 trie entry node
 */
static void
trie_entry_remove(struct lpm128_trie *lpm128_trie, struct lpm128_trie_entry *current,
                  struct lpm128_trie_entry *parent, uint32_t current_slot)
{
    /*
     * Case 1: The current node has both left and right subtrees. In this
     * case the trie structure does not need to be changed. All we need to
     * do is null out the current node value
     */
    if (current->left != SLOT_INVALID && current->right != SLOT_INVALID) {
        current->value = NULL;
        return;
    }

    /*
     * Case 2: If current node has only one child present, then the current
     * node is removed and that child takes its place in the trie.
     * This case also handles a node with no children.
     */
    struct lpm128_trie_entry *current_child = NULL;
    uint32_t current_child_slot = SLOT_INVALID;
    if (current->left != SLOT_INVALID) {
        current_child = lpm128_trie_entry_object(lpm128_trie, current->left);
        current_child_slot = current->left;
    } else if (current->right != SLOT_INVALID) {
        current_child = lpm128_trie_entry_object(lpm128_trie, current->right);
        current_child_slot = current->right;
    }

    /*
     * We need to update the number of bits to match on in the currentChild
     */
    if (current_child != NULL) {
        current_child->match_bit_count += current->match_bit_count;
    }

    /*
     * Case 2a: If current is the root node, then its child becomes the
     * root node. If there is no child of the current node, then root
     * becomes null
     */
    if (lpm128_trie->root == current_slot) {
        lpm128_trie->root = current_child_slot;
        slot_allocator_free(lpm128_trie->lpm128_trie_entry_allocator, current_slot);
        return;
    }

    /*
     * Case 2b: if the current node is not root, then we need to update the
     * parent node
     */
    bool is_current_left_child = false;
    if (parent->left == current_slot) {
        is_current_left_child = true;
    }

    if (is_current_left_child) {
        parent->left = current_child_slot;
    } else {
        parent->right = current_child_slot;
    }

    /*
     * If the currentChild was not null, then we are done since the parent
     * node was required before this remove operation and the parent node
     * still has the subtree where the current node was
     */
    if (current_child != NULL) {
        slot_allocator_free(lpm128_trie->lpm128_trie_entry_allocator, current_slot);
        return;
    }

    /*
     * If the parent node has no value present, then the parent node can
     * also be removed. Its place can be taken over by its remaining child.
     * Since we do not want to update the grand parent subtree, we need to
     * copy over the value from the remaining child.
     */
    if (parent->value != NULL) {
        slot_allocator_free(lpm128_trie->lpm128_trie_entry_allocator, current_slot);
        return;
    }

    /*
     * Since parent is an internal node, it will have two children
     * one of which is currently being deleted
     */
    struct lpm128_trie_entry *sibling;
    uint32_t sibling_slot;
    if (is_current_left_child) {
        sibling = lpm128_trie_entry_object(lpm128_trie, parent->right);
        sibling_slot = parent->right;
    } else {
        sibling = lpm128_trie_entry_object(lpm128_trie, parent->left);
        sibling_slot = parent->left;
    }

    AIM_ASSERT(sibling != NULL, "sibling can not be NULL if parent is an internal node");

    parent->key = sibling->key;
    parent->mask_len = sibling->mask_len;
    parent->left = sibling->left;
    parent->right = sibling->right;
    parent->value = sibling->value;

    parent->match_bit_count += sibling->match_bit_count;
    slot_allocator_free(lpm128_trie->lpm128_trie_entry_allocator, sibling_slot);
    slot_allocator_free(lpm128_trie->lpm128_trie_entry_allocator, current_slot);
    return;
}

/*
 * Documented in lpm128.h
 */
struct lpm128_trie *
lpm128_trie_create(void)
{
    struct lpm128_trie *lpm128_trie = aim_zmalloc(sizeof(struct lpm128_trie));

    lpm128_trie->lpm128_trie_entry_allocator = slot_allocator_create(LPM128_TRIE_ENTRY_COUNT);
    lpm128_trie->lpm128_trie_entries = aim_malloc(LPM128_TRIE_INITIAL_ALLOCATION *
                                            sizeof(struct lpm128_trie_entry));
    lpm128_trie->root = SLOT_INVALID;
    lpm128_trie->size = 0;
    lpm128_trie->allocated = LPM128_TRIE_INITIAL_ALLOCATION;

    return lpm128_trie;
}

/*
 * Documented in lpm128.h
 */
void
lpm128_trie_destroy(struct lpm128_trie *lpm128_trie)
{
    AIM_ASSERT(lpm128_trie != NULL, "attempted to delete a NULL lpm128 trie");
    AIM_ASSERT(lpm128_trie->root == SLOT_INVALID, "attempted to delete a non empty lpm128 trie");

    slot_allocator_destroy(lpm128_trie->lpm128_trie_entry_allocator);
    aim_free(lpm128_trie->lpm128_trie_entries);
    aim_free(lpm128_trie);
}

/*
 * Documented in lpm128.h
 */
bool
lpm128_trie_is_empty(struct lpm128_trie *lpm128_trie)
{
    AIM_ASSERT(lpm128_trie != NULL, "attempted to determine the size of a NULL lpm128 trie");

    return (lpm128_trie->size == 0)? true : false;
}

/*
 * Documented in lpm128.h
 */
int
lpm128_trie_insert(struct lpm128_trie *lpm128_trie, uint64_t key,
                uint8_t key_mask_len, void *value)
{
    AIM_ASSERT(lpm128_trie != NULL, "attempted to insert a entry in a NULL lpm128 trie");
    AIM_ASSERT(value != NULL, "attempted to insert a entry with NULL value in lpm128 trie");

    /*
     * Max entries per lpm128 trie is LPM128_TRIE_ENTRY_COUNT/2.
     */
    if (lpm128_trie->size == LPM128_TRIE_ENTRY_COUNT/2) {
        AIM_LOG_ERROR("Attempted to insert a entry in a full lpm128 trie");
        return -1;
    }

    /*
     * Make sure the key matches the mask.
     */
    AIM_ASSERT(key == (key & netmask(key_mask_len)), "key doesn't matches the mask");

    AIM_LOG_TRACE("Add lpm128 trie entry with ipv6 key=%"PRIx64"/%u", key, key_mask_len);

    if (lpm128_trie->root == SLOT_INVALID) {
        /* First entry */
        lpm128_trie->root = trie_entry_create(lpm128_trie, key, key_mask_len,
                                           key_mask_len, value, SLOT_INVALID,
                                           SLOT_INVALID);
        lpm128_trie->size += 1;
        return 0;
    }

    /*
     * Find closest matching leaf node.
     */
    uint32_t current_idx = lpm128_trie->root;
    struct lpm128_trie_entry *current = lpm128_trie_entry_object(lpm128_trie, current_idx);

    /*
     * index is the count of the number of bits matched for the current node
     */
    int index = 0;

    /*
     * total_index is the total number of bits that have been matched from
     * the root node to the current node
     */
    int total_index = 0;

    while (true) {
        while (index < current->match_bit_count) {
            bool current_bit = is_bit_set(current->key, total_index + index);

            if ((total_index + index) >= key_mask_len) {

                /*
                 * The new key is shorter than the match bits on the
                 * existing node. This key will become a new node and the
                 * existing node will become its subtree.
                 * Note in this case the position of the 'current' node is
                 * not changed so that the parent pointers dont need to be
                 * updated
                 */

                /*
                 * Copy the contents of the old current node to the new entry
                 */
                uint32_t entry_slot = trie_entry_create(lpm128_trie, current->key,
                                                        current->mask_len,
                                                        current->match_bit_count-index,
                                                        current->value, current->left,
                                                        current->right);
                current = lpm128_trie_entry_object(lpm128_trie, current_idx);

                /* The current node has the new key and value */
                current->key = key;
                current->mask_len = key_mask_len;
                current->value = value;
                current->match_bit_count = index;

                /* Bit set means left child, else right child */
                if (current_bit) {
                    current->left = entry_slot;
                    current->right = SLOT_INVALID;
                } else {
                    current->left = SLOT_INVALID;
                    current->right = entry_slot;
                }

                lpm128_trie->size += 1;
                return 0;
            }

            bool key_bit = is_bit_set(key, total_index + index);
            if (current_bit != key_bit) {

                /*
                 * more remaining on both current node key and new key.
                 * need to split node here
                 */
                uint32_t new_entry_slot = trie_entry_create(lpm128_trie, key,
                                                            key_mask_len,
                                                            key_mask_len-total_index-index,
                                                            value, SLOT_INVALID, SLOT_INVALID);
                current = lpm128_trie_entry_object(lpm128_trie, current_idx);

                uint32_t old_entry_slot = trie_entry_create(lpm128_trie,
                                                            current->key,
                                                            current->mask_len,
                                                            current->match_bit_count-index,
                                                            current->value, current->left,
                                                            current->right);
                current = lpm128_trie_entry_object(lpm128_trie, current_idx);

                /*
                 * set up new intermediate node and truncate its match_bit_count
                 * The trie entry can contain either of the two keys.
                 * We use the old one
                 */
                current->match_bit_count = index;
                current->value = NULL;

                if (key_bit) {
                    /* new link will be left tree */
                    current->left = new_entry_slot;
                    current->right = old_entry_slot;
                } else {
                    /* new link will be right tree */
                    current->left = old_entry_slot;
                    current->right = new_entry_slot;
                }

                lpm128_trie->size += 1;
                return 0;
            }

            index += 1;
        }

        /*
         * Completely matched the key in the node.
         * Traverse its branches
         * Used bits are the remaining mask bits in the key
         */
        if ((total_index + index) < key_mask_len) {

            if (is_bit_set(key, total_index + index)) {
                /* left branch */
                if (current->left == SLOT_INVALID) {
                    uint32_t entry_slot = trie_entry_create(lpm128_trie, key,
                                                            key_mask_len,
                                                            key_mask_len-total_index-index,
                                                            value, SLOT_INVALID,
                                                            SLOT_INVALID);
                    current = lpm128_trie_entry_object(lpm128_trie, current_idx);
                    current->left = entry_slot;
                    lpm128_trie->size += 1;
                    return 0;
                }
                current_idx = current->left;
                current = lpm128_trie_entry_object(lpm128_trie, current_idx);
            } else {
                /* right branch */
                if (current->right == SLOT_INVALID) {
                    uint32_t entry_slot = trie_entry_create(lpm128_trie, key,
                                                            key_mask_len,
                                                            key_mask_len-total_index-index,
                                                            value, SLOT_INVALID,
                                                            SLOT_INVALID);
                    current = lpm128_trie_entry_object(lpm128_trie, current_idx);
                    current->right = entry_slot;
                    lpm128_trie->size += 1;
                    return 0;
                }
                current_idx = current->right;
                current = lpm128_trie_entry_object(lpm128_trie, current_idx);
            }

            total_index += index;
            index = 0;
        } else {

            /*
             * Its either an exact match for existing leaf or
             * the match_bit_count of an internal node matches the new key
             *
             * Overwriting the current node
             */
            if (current->value == NULL) {
                lpm128_trie->size += 1;
            }

            current->key = key;
            current->mask_len = key_mask_len;
            current->value = value;
            return 0;
        }
    }
}

/*
 * Documented in lpm128.h
 */
void *
lpm128_trie_search(struct lpm128_trie *lpm128_trie, uint64_t key)
{
    AIM_ASSERT(lpm128_trie != NULL, "attempted to search for a entry in a NULL lpm128 trie");

    void *result_value = NULL;

    uint32_t current_slot = lpm128_trie->root;

    int total_index = 0;

    AIM_LOG_TRACE("Search lpm128 trie for key=%"PRIx64, key);

    while (current_slot != SLOT_INVALID) {
        struct lpm128_trie_entry *current = lpm128_trie_entry_object(lpm128_trie, current_slot);
        uint64_t mask = netmask(total_index + current->match_bit_count);
        if ((current->key & mask) != (key & mask)) {
            return result_value;
        }

        if (current->value != NULL) {
            AIM_LOG_TRACE("Found lpm128 trie entry with ipv6=%"PRIx64"/%u for "
                          "key=%"PRIx64, current->key, current->mask_len, key);
            result_value = current->value;
        }

        total_index += current->match_bit_count;
        if (is_bit_set(key, total_index)) {
            current_slot = current->left;
        } else {
            current_slot = current->right;
        }
    }

    return result_value;
}

/*
 * Documented in lpm128.h
 */
void
lpm128_trie_remove(struct lpm128_trie *lpm128_trie, uint64_t key, uint8_t key_mask_len)
{
    AIM_ASSERT(lpm128_trie != NULL, "attempted to remove a entry in a NULL lpm128 trie");

    struct lpm128_trie_entry *parent = NULL;
    uint32_t current_slot = lpm128_trie->root;

    int total_index = 0;

    AIM_LOG_TRACE("Remove lpm128 trie entry with ipv6 key=%"PRIx64"/%u", key, key_mask_len);

    while (current_slot != SLOT_INVALID) {
        struct lpm128_trie_entry *current = lpm128_trie_entry_object(lpm128_trie, current_slot);

        /*
         * Current node has a longer mask_len than the query
         * The key requested to be deleted is not present in the trie
         */
        if ((key_mask_len - total_index) < current->match_bit_count) {
            AIM_LOG_TRACE("No lpm128 trie entry present with ipv4=%"PRIx64"/%u",
                          key, key_mask_len);
            return;
        }

        uint64_t mask = netmask(total_index + current->match_bit_count);
        if ((current->key & mask) != (key & mask)) {
            return;
        }

        total_index += current->match_bit_count;
        if (total_index == key_mask_len) {
            /* Found the node */
            if (current->value != NULL) {
                trie_entry_remove(lpm128_trie, current, parent, current_slot);
                lpm128_trie->size -= 1;
            }
            return;
        }

        parent = current;
        if (is_bit_set(key, total_index)) {
            current_slot = current->left;
        } else {
            current_slot = current->right;
        }
    }

    return;
}
