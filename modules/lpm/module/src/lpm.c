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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

/*
 * See the comments in lpm.h for a high level description.
 */

#include <AIM/aim.h>
#include "lpm_int.h"
#include "lpm_log.h"

/*
 * Private function used to return whether
 * or not bit 'i' counting from the MSB is set in 'key'.
 */
static bool
is_bit_set(uint32_t key, int i)
{
    return key & (1 << (31-i));
}

/*
 * Compute netmask address given prefix
 */
static uint32_t
netmask(int prefix)
{
    if (prefix == 0)
        return(~((uint32_t) -1));
    else
        return(~((1 << (32 - prefix)) - 1));
}

/*
 * Create a lpm trie entry node
 */
static struct lpm_trie_entry *
trie_entry_create(uint32_t key, uint8_t mask_len, uint8_t bit, void *value)
{
    AIM_LOG_TRACE("Create lpm trie entry with ipv4=%{ipv4a}/%u, bit=%u",
                  key, mask_len, bit);

    struct lpm_trie_entry *entry = aim_zmalloc(sizeof(struct lpm_trie_entry));

    entry->key = key;
    entry->mask_len = mask_len;
    entry->match_bit_count = bit;
    entry->value = value;
    entry->left = NULL;
    entry->right = NULL;

    return entry;
}

/*
 * Remove a lpm trie entry node
 */
static void
trie_entry_remove(struct lpm_trie *lpm_trie, struct lpm_trie_entry *current,
                  struct lpm_trie_entry *parent)
{
    /*
     * Case 1: The current node has both left and right subtrees. In this
     * case the trie structure does not need to be changed. All we need to
     * do is null out the current node value
     */
    if (current->left != NULL && current->right != NULL) {
        current->value = NULL;
        return;
    }

    /*
     * Case 2: If current node has only one child present, then the current
     * node is removed and that child takes its place in the trie.
     * This case also handles a node with no children.
     */
    struct lpm_trie_entry *current_child = NULL;
    if (current->left != NULL) {
        current_child = current->left;
    } else if (current->right != NULL) {
        current_child = current->right;
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
    if (lpm_trie->root == current) {
        lpm_trie->root = current_child;
        aim_free(current);
        return;
    }

    /*
     * Case 2b: if the current node is not root, then we need to update the
     * parent node
     */
    bool is_current_left_child = false;
    if (parent->left == current) {
        is_current_left_child = true;
    }

    if (is_current_left_child) {
        parent->left = current_child;
    } else {
        parent->right = current_child;
    }

    /*
     * If the currentChild was not null, then we are done since the parent
     * node was required before this remove operation and the parent node
     * still has the subtree where the current node was
     */
    if (current_child != NULL) {
        aim_free(current);
        return;
    }

    /*
     * If the parent node has no value present, then the parent node can
     * also be removed. Its place can be taken over by its remaining child.
     * Since we do not want to update the grand parent subtree, we need to
     * copy over the value from the remaining child.
     */
    if (parent->value != NULL) {
        aim_free(current);
        return;
    }

    /*
     * Since parent is an internal node, it will have two children
     * one of which is currently being deleted
     */
    struct lpm_trie_entry *sibling;
    if (is_current_left_child) {
        sibling = parent->right;
    } else {
        sibling = parent->left;
    }

    AIM_ASSERT(sibling != NULL, "sibling can not be NULL if parent is an internal node");

    parent->key = sibling->key;
    parent->mask_len = sibling->mask_len;
    parent->left = sibling->left;
    parent->right = sibling->right;
    parent->value = sibling->value;

    parent->match_bit_count += sibling->match_bit_count;
    aim_free(sibling);
    aim_free(current);
    return;
}

/*
 * Documented in lpm.h
 */
struct lpm_trie *
lpm_trie_create(void)
{
    struct lpm_trie *lpm_trie = aim_zmalloc(sizeof(struct lpm_trie));

    lpm_trie->root = NULL;
    lpm_trie->size = 0;

    return lpm_trie;
}

/*
 * Documented in lpm.h
 */
void
lpm_trie_destroy(struct lpm_trie *lpm_trie)
{
    AIM_ASSERT(lpm_trie != NULL, "attempted to delete a NULL lpm trie");
    AIM_ASSERT(lpm_trie->root == NULL, "attempted to delete a non empty lpm trie");

    aim_free(lpm_trie);
}

/*
 * Documented in lpm.h
 */
bool
lpm_trie_is_empty(struct lpm_trie *lpm_trie)
{
    AIM_ASSERT(lpm_trie != NULL, "attempted to determine the size of a NULL lpm trie");

    return (lpm_trie->size == 0)? true : false;
}

/*
 * Documented in lpm.h
 */
void
lpm_trie_insert(struct lpm_trie *lpm_trie, uint32_t key,
                uint8_t key_mask_len, void *value)
{
    AIM_ASSERT(lpm_trie != NULL, "attempted to insert a entry in a NULL lpm trie");
    AIM_ASSERT(value != NULL, "attempted to insert a entry with NULL value in lpm trie");

    /*
     * Make sure the key matches the mask.
     */
    AIM_ASSERT(key == (key & netmask(key_mask_len)), "key doesn't matches the mask");

    AIM_LOG_TRACE("Add lpm trie entry with ipv4=%{ipv4a}/%u", key, key_mask_len);

    if (lpm_trie->root == NULL) {
        /* First entry */
        lpm_trie->root = trie_entry_create(key, key_mask_len, key_mask_len, value);
        lpm_trie->size += 1;
        return;
    }

    /*
     * Find closest matching leaf node.
     */
    struct lpm_trie_entry *current = lpm_trie->root;

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
                struct lpm_trie_entry *entry = trie_entry_create(current->key,
                                                                 current->mask_len,
                                                                 current->match_bit_count-index,
                                                                 current->value);

                entry->left = current->left;
                entry->right = current->right;

                /* The current node has the new key and value */
                current->key = key;
                current->mask_len = key_mask_len;
                current->value = value;
                current->match_bit_count = index;

                /* Bit set means left child, else right child */
                if (current_bit) {
                    current->left = entry;
                    current->right = NULL;
                } else {
                    current->left = NULL;
                    current->right = entry;
                }

                lpm_trie->size += 1;
                return;
            }

            bool key_bit = is_bit_set(key, total_index + index);
            if (current_bit != key_bit) {

                /*
                 * more remaining on both current node key and new key.
                 * need to split node here
                 */
                struct lpm_trie_entry *new_entry = trie_entry_create(key,
                                                   key_mask_len,
                                                   key_mask_len-total_index-index,
                                                   value);

                struct lpm_trie_entry *old_entry = trie_entry_create(
                                                   current->key,
                                                   current->mask_len,
                                                   current->match_bit_count-index,
                                                   current->value);

                old_entry->left = current->left;
                old_entry->right = current->right;

                /*
                 * set up new intermediate node and truncate its match_bit_count
                 * The trie entry can contain either of the two keys.
                 * We use the old one
                 */
                current->match_bit_count = index;
                current->value = NULL;

                if (key_bit) {
                    /* new link will be left tree */
                    current->left = new_entry;
                    current->right = old_entry;
                } else {
                    /* new link will be right tree */
                    current->left = old_entry;
                    current->right = new_entry;
                }

                lpm_trie->size += 1;
                return;
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
                if (current->left == NULL) {
                    current->left = trie_entry_create(key, key_mask_len,
                                                      key_mask_len-total_index-index,
                                                      value);
                    lpm_trie->size += 1;
                    return;
                }
                current = current->left;
            } else {
                /* right branch */
                if (current->right == NULL) {
                    current->right = trie_entry_create(key, key_mask_len,
                                                       key_mask_len-total_index-index,
                                                       value);
                    lpm_trie->size += 1;
                    return;
                }
                current = current->right;
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
                lpm_trie->size += 1;
            }

            current->key = key;
            current->mask_len = key_mask_len;
            current->value = value;
            return;
        }
    }
}

/*
 * Documented in lpm.h
 */
void *
lpm_trie_search(struct lpm_trie *lpm_trie, uint32_t key)
{
    AIM_ASSERT(lpm_trie != NULL, "attempted to search for a entry in a NULL lpm trie");

    void *result_value = NULL;

    struct lpm_trie_entry *current = lpm_trie->root;

    int total_index = 0;

    AIM_LOG_TRACE("Search lpm trie for key=%{ipv4a}", key);

    while (current != NULL) {
        uint32_t mask = netmask(total_index + current->match_bit_count);
        if ((current->key & mask) != (key & mask)) {
            return result_value;
        }

        if (current->value != NULL) {
            AIM_LOG_TRACE("Found lpm trie entry with ipv4=%{ipv4a}/%u for "
                          "key=%{ipv4a}", current->key, current->mask_len, key);
            result_value = current->value;
        }

        total_index += current->match_bit_count;
        if (is_bit_set(key, total_index)) {
            current = current->left;
        } else {
            current = current->right;
        }
    }

    return result_value;
}

/*
 * Documented in lpm.h
 */
void
lpm_trie_remove(struct lpm_trie *lpm_trie, uint32_t key, uint8_t key_mask_len)
{
    AIM_ASSERT(lpm_trie != NULL, "attempted to remove a entry in a NULL lpm trie");

    struct lpm_trie_entry *parent = NULL;
    struct lpm_trie_entry *current = lpm_trie->root;

    int total_index = 0;

    AIM_LOG_TRACE("Remove lpm trie entry with ipv4=%{ipv4a}/%u", key, key_mask_len);

    while (current != NULL) {

        /*
         * Current node has a longer mask_len than the query
         * The key requested to be deleted is not present in the trie
         */
        if ((key_mask_len - total_index) < current->match_bit_count) {
            AIM_LOG_TRACE("No lpm trie entry present with ipv4=%{ipv4a}/%u",
                          key, key_mask_len);
            return;
        }

        uint32_t mask = netmask(total_index + current->match_bit_count);
        if ((current->key & mask) != (key & mask)) {
            return;
        }

        total_index += current->match_bit_count;
        if (total_index == key_mask_len) {
            /* Found the node */
            if (current->value != NULL) {
                trie_entry_remove(lpm_trie, current, parent);
                lpm_trie->size -= 1;
            }
            return;
        }

        parent = current;
        if (is_bit_set(key, total_index)) {
            current = current->left;
        } else {
            current = current->right;
        }
    }

    return;
}
