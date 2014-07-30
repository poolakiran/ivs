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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lpm/lpm.h>
#include <assert.h>
#include <arpa/inet.h>
#include <AIM/aim.h>

struct l3_cidr_route_entry {
    uint32_t key;
    uint32_t mask;
    uint32_t value;
};

#define NUM_ENTRIES 16000
#define DEBUG 0

static struct l3_cidr_route_entry route_entries[NUM_ENTRIES];

struct lpm_trie *lpm_trie;

static uint32_t
convert_ip(const char *ip_str)
{
    struct sockaddr_in sa;
    inet_pton(AF_INET, ip_str, &(sa.sin_addr));
    return ntohl(sa.sin_addr.s_addr);
}

#ifndef DEBUG
static char ip_str[INET_ADDRSTRLEN];
static char *
get_ip(uint32_t ip)
{
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &(sa.sin_addr), ip_str, INET_ADDRSTRLEN);
    return ip_str;

}

static void
print_preorder(struct lpm_trie_entry *entry)
{
    if (entry == NULL) return;

    printf("ipv4: %s/%u, bit: %u, value: %x\n",
           get_ip(entry->key), entry->mask_len, entry->match_bit_count,
           entry->value? *(uint32_t *)entry->value: 0);

    print_preorder(entry->left);
    print_preorder(entry->right);
}
#endif

static void
insert(char *key, char *mask, uint32_t value,
       struct l3_cidr_route_entry *route_entry, uint32_t size)
{
    assert(lpm_trie != NULL);

    route_entry->key = convert_ip(key);;
    route_entry->mask = convert_ip(mask);
    route_entry->value = value;
    lpm_trie_insert(lpm_trie, route_entry->key, route_entry->mask, &route_entry->value);
    assert(lpm_trie->size == size);
}

static void
search(char *key, uint32_t *expected_value)
{
    assert(lpm_trie != NULL);

    uint32_t *value = lpm_trie_search(lpm_trie, convert_ip(key));

#ifndef DEBUG
    printf("lpm for ipv4: %s, value: %x\n", key, value? *(uint32_t *)value: 0);
#endif

    assert(expected_value == value);
}

static void
delete(char *key, char *mask, uint32_t size)
{
    assert(lpm_trie != NULL);

    lpm_trie_remove(lpm_trie, convert_ip(key), convert_ip(mask));
    assert(lpm_trie->size == size);
}

static void
test_basic(void)
{
    uint32_t size = 0;

    lpm_trie = lpm_trie_create();

    insert("192.168.0.0", "255.255.0.0", 0xa, &route_entries[0], ++size);
    insert("192.168.2.0", "255.255.255.0", 0xb, &route_entries[1], ++size);
    insert("192.168.3.0", "255.255.255.0", 0xc, &route_entries[2], ++size);
    insert("10.0.0.0", "255.0.0.0", 0xd, &route_entries[3], ++size);
    insert("10.1.1.0", "255.255.255.0", 0xe, &route_entries[4], ++size);

    /* Add a default route */
    insert("0.0.0.0", "0.0.0.0", 0xf, &route_entries[5], ++size);

    insert("10.1.0.0", "255.255.0.0", 0x10, &route_entries[6], ++size);
    insert("128.0.0.0", "255.0.0.0", 0x11, &route_entries[7], ++size);
    insert("192.168.3.252", "255.255.255.252", 0x12, &route_entries[8], ++size);

#ifndef DEBUG
    print_preorder(lpm_trie->root);
#endif

    search("192.168.2.20", &route_entries[1].value);
    search("192.168.3.20", &route_entries[2].value);
    search("192.168.3.254", &route_entries[8].value);
    search("10.1.1.1", &route_entries[4].value);

    /* Miss in the lpm should match default route */
    search("160.90.125.0", &route_entries[5].value);
    search("4.4.4.0", &route_entries[5].value);

    /* Remove the default route which is also the root node */
    delete("0.0.0.0", "0.0.0.0", --size);
    delete("192.168.2.0", "255.255.255.0", --size);
    delete("10.1.1.0", "255.255.255.0", --size);
    delete("128.0.0.0", "255.0.0.0", --size);

    search("0.0.0.0", NULL);
    search("192.168.2.0", &route_entries[0].value);
    search("10.1.1.1", &route_entries[6].value);

    /* Miss in the lpm should not match anything */
    search("160.90.125.0", NULL);
    search("4.4.4.0", NULL);

    /* Test for duplicate entry with modified value */
    insert("192.168.3.252", "255.255.255.252", 0x13, &route_entries[9], size);
    search("192.168.3.254", &route_entries[9].value);

    /* After we remove the previous lpm we should match on the next */
    delete("192.168.3.252", "255.255.255.252", --size);
    search("192.168.3.254", &route_entries[2].value);

    delete("192.168.3.0", "255.255.255.0", --size);
    delete("10.1.0.0", "255.255.0.0", --size);

    /* Try to delete non-existant values in the trie */
    delete("192.168.3.253", "255.255.255.252", size);

    search("192.168.3.20", &route_entries[0].value);
    search("10.1.1.1", &route_entries[3].value);

    delete("192.168.0.0", "255.255.0.0", --size);
    delete("10.0.0.0", "255.0.0.0", --size);

    /* Verify that the trie is empty after all the operations */
    assert(lpm_trie->size == 0);
    lpm_trie_destroy(lpm_trie);

    memset(route_entries, 0, sizeof(route_entries));
}

static uint32_t
make_ip()
{
    uint32_t random_ip = rand();
    return (random_ip >> 24 & 0xFF) << 24 |
           (random_ip >> 16 & 0xFF) << 16 |
           (random_ip >> 8 & 0xFF) << 8 |
           (random_ip & 0xFF);
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

static void
test_random()
{
    const int num_masks = 32;
    const int num_lookups = 10000;

    lpm_trie = lpm_trie_create();

    int i;
    uint32_t key, mask;

    /* Add entries */
    for (i = 0; i < NUM_ENTRIES; i++) {
        key = make_ip();
        mask = netmask(rand() % num_masks);
        key &= mask;
        route_entries[i].key = key;
        route_entries[i].mask = mask;
        route_entries[i].value = rand();

#ifndef DEBUG
        printf("ip = %s, mask = %x, value: %u\n", get_ip(key), mask,
               route_entries[i].value);
#endif

        lpm_trie_insert(lpm_trie, key, mask, &route_entries[i].value);
    }

    /* Random lookups */
    for (i = 0; i < num_lookups; i++) {
        key = make_ip();

        /* Lookup in the trie for lpm associated with the key */
        uint32_t *lpm_value = lpm_trie_search(lpm_trie, key);

        /* Linear search to find longest prefix match */
        int j;
        uint32_t lpm_mask = 0;
        uint32_t *ref_value = NULL;
        for (j = NUM_ENTRIES-1; j >= 0; j--) {
            if ((key & route_entries[j].mask) == route_entries[j].key &&
                route_entries[j].mask > lpm_mask) {
                ref_value = &route_entries[j].value;
                lpm_mask = route_entries[j].mask;
            }
        }

#ifndef DEBUG
        printf("lpm for ipv4: %s, lpm_value: %u, ref_value: %u\n", get_ip(key),
               lpm_value? *(uint32_t *)lpm_value: 0,
               ref_value? *(uint32_t *)ref_value: 0);
#endif

        AIM_ASSERT(lpm_value == ref_value, "mismatch with reference");
    }

    /* Remove entries */
    for (i = 0; i < NUM_ENTRIES; i++) {
        lpm_trie_remove(lpm_trie, route_entries[i].key, route_entries[i].mask);
    }

    /* Verify that the trie is empty after all the operations */
    assert(lpm_trie->size == 0);
    lpm_trie_destroy(lpm_trie);

    memset(route_entries, 0, sizeof(route_entries));
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_random();

    return 0;
}
