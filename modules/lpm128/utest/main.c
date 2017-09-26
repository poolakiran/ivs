/****************************************************************
 *
 *        Copyright 2017, Big Switch Networks, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lpm128/lpm128.h>
#include <lpm128_int.h>
#include <assert.h>
#include <arpa/inet.h>
#include <AIM/aim.h>

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

struct l3_cidr_route_entry {
    uint64_t key;
    uint8_t mask_len;
    uint32_t value;
    struct in6_addr sin6_addr;
    bool valid;
};

#define NUM_ENTRIES 16000
#define DEBUG 0

static struct l3_cidr_route_entry route_entries[NUM_ENTRIES];

struct lpm128_trie *lpm128_trie;

static uint64_t
ipv6_to_key(const char *ip_str)
{
    struct in6_addr sin6_addr;
    inet_pton(AF_INET6, ip_str, &sin6_addr);
    return(ntohll(*((uint64_t *)&sin6_addr.s6_addr[0])));
}

#ifndef DEBUG
#define LPM128_TRIE_ENTRY_OBJECT(lpm128_trie, slot) &((lpm128_trie)->lpm128_trie_entries[slot])
static char ip_str[INET6_ADDRSTRLEN];
static char *
key_to_ipv6(uint64_t ip)
{
    struct in6_addr sin6_addr;
    ip = htonll(ip);
    memcpy(&sin6_addr, &ip, sizeof(uint64_t));
    inet_ntop(AF_INET6, &sin6_addr, ip_str, sizeof(ip_str));
    return ip_str;

}

static void
print_preorder(uint32_t slot)
{
    if (slot == SLOT_INVALID) return;

    struct lpm128_trie_entry *entry = LPM128_TRIE_ENTRY_OBJECT(lpm128_trie, slot);
    printf("ipv6: %s/%u, bit: %u, value: %x\n",
           key_to_ipv6(entry->key), entry->mask_len, entry->match_bit_count,
           entry->value? *(uint32_t *)entry->value: 0);

    print_preorder(entry->left);
    print_preorder(entry->right);
}
#endif

static void
insert(char *key, uint8_t mask_len, uint32_t value,
       struct l3_cidr_route_entry *route_entry, uint32_t size)
{
    assert(lpm128_trie != NULL);

    route_entry->key = ipv6_to_key(key);;
    route_entry->mask_len = mask_len;
    route_entry->value = value;
    inet_pton(AF_INET6, key, &route_entry->sin6_addr);
    lpm128_trie_insert(lpm128_trie, route_entry->key, route_entry->mask_len,
                      &route_entry->value);
    assert(lpm128_trie->size == size);
}

static void
search(char *key, uint32_t *expected_value)
{
    assert(lpm128_trie != NULL);

    uint32_t *value = lpm128_trie_search(lpm128_trie, ipv6_to_key(key));

#ifndef DEBUG
    printf("lpm for ipv6: %s, value: %x\n", key, value? *(uint32_t *)value: 0);
#endif

    assert(expected_value == value);
}

static void
delete(char *key, uint8_t mask_len, uint32_t size)
{
    assert(lpm128_trie != NULL);

    lpm128_trie_remove(lpm128_trie, ipv6_to_key(key), mask_len);
    assert(lpm128_trie->size == size);
}

static void
test_basic(void)
{
    uint32_t size = 0;

    memset(route_entries, 0, sizeof(route_entries));

    lpm128_trie = lpm128_trie_create();

    insert("192:168:0:0::", 32, 0xa, &route_entries[0], ++size);
    insert("192:168:2:0::", 48, 0xb, &route_entries[1], ++size);
    insert("192:168:3:0::", 48, 0xc, &route_entries[2], ++size);
    insert("10:0:0:0::", 16, 0xd, &route_entries[3], ++size);
    insert("10:1:1:0::", 48, 0xe, &route_entries[4], ++size);

    /* Add a default route */
    insert("::", 0, 0xf, &route_entries[5], ++size);

    insert("10:1:0:0::", 32, 0x10, &route_entries[6], ++size);
    insert("128:0:0:0::", 16, 0x11, &route_entries[7], ++size);
    insert("192:168:3:25f0::", 60, 0x12, &route_entries[8], ++size);

#ifndef DEBUG
    print_preorder(lpm128_trie->root);
#endif

    search("192:168:2:20::", &route_entries[1].value);
    search("192:168:3:20::", &route_entries[2].value);
    search("192:168:3:25f1::", &route_entries[8].value);
    search("10:1:1:1::", &route_entries[4].value);

    /* Miss in the lpm should match default route */
    search("160:90:125:0::", &route_entries[5].value);
    search("4:4:4:0::", &route_entries[5].value);

    /* Remove the default route which is also the root node */
    delete("::", 0, --size);
    delete("192:168:2:0::", 48, --size);
    delete("10:1:1:0::", 48, --size);
    delete("128:0:0:0::", 16, --size);

    search("::", NULL);
    search("192:168:2:0::", &route_entries[0].value);
    search("10:1:1:1::", &route_entries[6].value);

    /* Miss in the lpm should not match anything */
    search("160:90:125:0::", NULL);
    search("4:4:4:0::", NULL);

    /* Test for duplicate entry with modified value */
    insert("192:168:3:25f0::", 60, 0x13, &route_entries[9], size);
    search("192:168:3:25f1::", &route_entries[9].value);

    /* After we remove the previous lpm we should match on the next */
    delete("192:168:3:25f0::", 60, --size);
    search("192:168:3:25f1::", &route_entries[2].value);

    delete("192:168:3:0::", 48, --size);
    delete("10:1:0:0::", 32, --size);

    /* Try to delete non-existant values in the trie */
    delete("192:168:3:25f3::", 60, size);

    search("192:168:3:20::", &route_entries[0].value);
    search("10:1:1:1::", &route_entries[3].value);

    delete("192:168:0:0::", 32, --size);
    delete("10:0:0:0::", 16, --size);

    /* Verify that the trie is empty after all the operations */
    assert(lpm128_trie->size == 0);
    lpm128_trie_destroy(lpm128_trie);
}

/*
 * Compute netmask address given prefix
 */
static uint64_t
netmask(int prefix)
{
    if (prefix == 0)
        return(~((uint64_t) -1));
    else
        return(~((1ULL << (64 - prefix)) - 1));
}

/*
 * Perform a linear search to find longest prefix match
 */
static void *
linear_search(uint64_t key)
{
    int i;
    int lpm128_mask_len = -1;
    uint32_t *value = NULL;
    for (i = NUM_ENTRIES-1; i >= 0; i--) {
        if (route_entries[i].valid == true &&
            (key & netmask(route_entries[i].mask_len)) == route_entries[i].key
            && route_entries[i].mask_len > lpm128_mask_len) {
            value = &route_entries[i].value;
            lpm128_mask_len = route_entries[i].mask_len;
        }
    }

    return value;
}

static uint64_t
make_ip (void)
{
    return rand() + rand();
}

static void
test_random()
{
    const int num_masks = 64;
    const int num_lookups = 10000;

    lpm128_trie = lpm128_trie_create();

    int i;
    uint64_t key;
    uint8_t mask_len;

    memset(route_entries, 0, sizeof(route_entries));

    /* Add entries */
    for (i = 0; i < NUM_ENTRIES; i++) {
        key = make_ip();
        mask_len = rand() % num_masks;
        key &= netmask(mask_len);
        route_entries[i].key = key;
        route_entries[i].mask_len = mask_len;
        route_entries[i].value = rand();
        route_entries[i].valid = true;

#ifndef DEBUG
        printf("insert ipv6 = %s/%u, value: %u\n", key_to_ipv6(key), mask_len,
               route_entries[i].value);
#endif

        lpm128_trie_insert(lpm128_trie, key, mask_len, &route_entries[i].value);
    }

    /* Random lookups */
    for (i = 0; i < num_lookups; i++) {
        key = make_ip();

        /* Lookup in the trie for lpm associated with the key */
        uint32_t *lpm128_value = lpm128_trie_search(lpm128_trie, key);

        /* Lookup in the route_entries array for lpm associated with the key */
        uint32_t *ref_value = linear_search(key);

#ifndef DEBUG
        printf("lpm for ipv6: %s, lpm128_value: %u, ref_value: %u\n", key_to_ipv6(key),
               lpm128_value? *(uint32_t *)lpm128_value: 0,
               ref_value? *(uint32_t *)ref_value: 0);
#endif

        AIM_ASSERT(lpm128_value == ref_value, "mismatch with reference");
    }

    /* Remove entries */
    for (i = 0; i < NUM_ENTRIES; i++) {
        lpm128_trie_remove(lpm128_trie, route_entries[i].key, route_entries[i].mask_len);
        route_entries[i].valid = false;
    }

    /* Verify that the trie is empty after all the operations */
    assert(lpm128_trie_is_empty(lpm128_trie) == true);
    lpm128_trie_destroy(lpm128_trie);
}

static bool
duplicate_key_mask(uint64_t key, uint8_t mask_len)
{
    int i;
    for (i = 0; i < NUM_ENTRIES; i++) {
        if (key == route_entries[i].key && mask_len == route_entries[i].mask_len) {
            return true;
        }
    }

    return false;
}

static void
test_mixed()
{
    const int num_masks = 64;
    const int num_lookups = 1000;

    lpm128_trie = lpm128_trie_create();

    int i;
    uint64_t key;
    uint8_t mask_len;

    memset(route_entries, 0, sizeof(route_entries));

    /* Add and Remove entries based on valid flag */
    for (i = 0; i < num_lookups; i++) {
        int index = rand() % NUM_ENTRIES;
        key = make_ip();
        mask_len = rand() % num_masks;
        key &= netmask(mask_len);
        if (route_entries[index].valid == false &&
            duplicate_key_mask(key, mask_len) == false) {
            route_entries[index].key = key;
            route_entries[index].mask_len = mask_len;
            route_entries[index].value = rand();
            route_entries[index].valid = true;

#ifndef DEBUG
            printf("insert ipv6 = %s/%u, value: %u\n", key_to_ipv6(key), mask_len,
                   route_entries[index].value);
#endif

            lpm128_trie_insert(lpm128_trie, key, mask_len, &route_entries[index].value);
        } else {
            lpm128_trie_remove(lpm128_trie, route_entries[index].key,
                              route_entries[index].mask_len);
            route_entries[index].valid = false;
        }

        /* Random lookups */
        int j;
        for (j = 0; j < num_lookups/10; j++) {
            key = make_ip();

            /* Lookup in the trie for lpm associated with the key */
            uint32_t *lpm128_value = lpm128_trie_search(lpm128_trie, key);

            /* Lookup in the route_entries array for lpm associated with the key */
            uint32_t *ref_value = linear_search(key);

            AIM_ASSERT(lpm128_value == ref_value, "mismatch with reference");
        }
    }

    /* Remove entries that are still valid */
    for (i = 0; i < NUM_ENTRIES; i++) {
        if (route_entries[i].valid == true) {
            lpm128_trie_remove(lpm128_trie, route_entries[i].key,
                              route_entries[i].mask_len);
            route_entries[i].valid = false;
        }
    }

    /* Verify that the trie is empty after all the operations */
    assert(lpm128_trie_is_empty(lpm128_trie) == true);
    lpm128_trie_destroy(lpm128_trie);
}

static void
test_churn()
{
    lpm128_trie = lpm128_trie_create();

    for (int i = 0; i < 100; i++) {
        for (uint64_t j = 0; j < 32; j++) {
            lpm128_trie_insert(lpm128_trie, j<<16, 48, (void *)1);
        }
        for (uint64_t j = 0; j < 32; j++) {
            lpm128_trie_remove(lpm128_trie, j<<16, 48);
        }
    }

    assert(lpm128_trie_is_empty(lpm128_trie) == true);
    lpm128_trie_destroy(lpm128_trie);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_random();
    test_mixed();
    test_churn();

    return 0;
}
