/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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
#include <AIM/aim.h>
#include <flowtable/flowtable.h>
#include <assert.h>

uint32_t ind_ovs_salt = 42;

static struct flowtable_key
make_key(uint64_t pattern)
{
    struct flowtable_key key;
    int i;

    for (i = 0; i < FLOWTABLE_KEY_SIZE/8; i++) {
        key.data[i] = pattern;
    }

    return key;
}

static struct flowtable_entry
make_flow(uint64_t key_pattern, uint64_t mask_pattern, uint16_t priority)
{
    struct flowtable_entry fte;
    struct flowtable_key key, mask;
    assert((key_pattern & mask_pattern) == key_pattern);
    key = make_key(key_pattern);
    mask = make_key(mask_pattern);
    flowtable_entry_init(&fte, &key, &mask, priority);
    return fte;
}

/* make_generic_key and make_generic_flow are used to generate
   unique flow mask, key combinations to test flowtable generic hash table */
static struct flowtable_key
make_generic_key(uint64_t pattern)
{
    return make_key(pattern << 32);
}

static struct flowtable_entry
make_generic_flow(uint64_t key_pattern, uint64_t mask_pattern, uint16_t priority)
{
    const int max_unique_masks = 1000;
    return make_flow(key_pattern << 32,
                     ((uint64_t)~0 << 32)|(mask_pattern % max_unique_masks), priority);
}

static void
test_basic(void)
{
    struct flowtable *ft = flowtable_create();

    struct flowtable_entry A, B, C, *match;
    struct flowtable_key P;

    /* Exact match, normal priority */
    A = make_flow(0x12345678, ~0, 1000);
    flowtable_insert(ft, &A);

    /* Exact match, low priority */
    B = make_flow(0x12345678, ~0, 0);
    flowtable_insert(ft, &B);

    /* Wildcarded, low priority */
    C = make_flow(0x00005678, 0x0000ffff, 0);
    flowtable_insert(ft, &C);

    /* Should match A */
    P = make_key(0x12345678);
    match = flowtable_match(ft, &P);
    assert(match == &A);

    /* Should match C */
    P = make_key(0x22345678);
    match = flowtable_match(ft, &P);
    assert(match == &C);

    /* Should not match anything */
    P = make_key(0x12345679);
    match = flowtable_match(ft, &P);
    assert(match == NULL);

    flowtable_destroy(ft);
}

/*
 * Higher priority entries in the wildcard bucket take precedence over
 * matches from a hash bucket.
 */
static void
test_wildcard_priority(void)
{
    struct flowtable *ft = flowtable_create();

    struct flowtable_entry A, B, *match;
    struct flowtable_key P;

    /* Exact match, normal priority */
    A = make_flow(0x12345678, ~0, 1000);
    flowtable_insert(ft, &A);

    /* Wildcarded, high priority */
    B = make_flow(0x00005678, 0x0000ffff, 2000);
    flowtable_insert(ft, &B);

    /* Should match B */
    P = make_key(0x22345678);
    match = flowtable_match(ft, &P);
    assert(match == &B);

    flowtable_destroy(ft);
}

/*
 * Overfill the table and ensure everything can still be matched.
 */
static void
test_collisions(void)
{
    const int n = 16384 * 3;
    struct flowtable *ft = flowtable_create();

    struct flowtable_entry *ftes = calloc(n, sizeof(*ftes));
    assert(ftes);

    int i;
    struct flowtable_key P;

    /* Add entries */
    for (i = 0; i < n; i++) {
        P = make_key(i);
        assert(flowtable_match(ft, &P) == NULL);
        ftes[i] = make_flow(i, ~0, 1000);
        flowtable_insert(ft, &ftes[i]);
        assert(flowtable_match(ft, &P) == &ftes[i]);
    }

    /* Match on overfull table */
    for (i = 0; i < n; i++) {
        P = make_key(i);
        assert(flowtable_match(ft, &P) == &ftes[i]);
    }

    /* Remove entries */
    for (i = 0; i < n; i++) {
        P = make_key(i);
        assert(flowtable_match(ft, &P) == &ftes[i]);
        flowtable_remove(ft, &ftes[i]);
        assert(flowtable_match(ft, &P) == NULL);
    }

    flowtable_destroy(ft);

    free(ftes);
}

static void
test_flowtable_generic_basic(void)
{
    struct flowtable *ftg = flowtable_create();

    struct flowtable_entry A, B, C, *match;
    struct flowtable_key P;

    /* Exact match, normal priority */
    A = make_flow(0x12345678, ~0, 1000);
    flowtable_insert(ftg, &A);

    /* Exact match, low priority */
    B = make_flow(0x12345678, ~0, 0);
    flowtable_insert(ftg, &B);

    /* Wildcarded, low priority */
    C = make_flow(0x00005678, 0x0000ffff, 0);
    flowtable_insert(ftg, &C);

    /* Should match A */
    P = make_key(0x12345678);
    match = flowtable_match(ftg, &P);
    assert(match == &A);

    /* Should match C */
    P = make_key(0x22345678);
    match = flowtable_match(ftg, &P);
    assert(match == &C);

    /* Should not match anything */
    P = make_key(0x12345679);
    match = flowtable_match(ftg, &P);
    assert(match == NULL);

    flowtable_remove(ftg, &A);
    flowtable_remove(ftg, &B);
    flowtable_remove(ftg, &C);

    flowtable_destroy(ftg);
}

/*
 * Higher priority entries in the wildcard bucket take precedence over
 * matches from a hash bucket.
 */
static void
test_flowtable_generic_wildcard_priority(void)
{
    struct flowtable *ftg = flowtable_create();

    struct flowtable_entry A, B, *match;
    struct flowtable_key P;

    /* Exact match, normal priority */
    A = make_flow(0x12345678, ~0, 1000);
    flowtable_insert(ftg, &A);

    /* Wildcarded, high priority */
    B = make_flow(0x00005678, 0x0000ffff, 2000);
    flowtable_insert(ftg, &B);

    /* Should match B */
    P = make_key(0x22345678);
    match = flowtable_match(ftg, &P);
    assert(match == &B);

    flowtable_destroy(ftg);
}

/*
 * Overfill the table and ensure everything can still be matched.
 */
static void
test_flowtable_generic_collisions(void)
{
    const int n = 16384 * 3;
    struct flowtable *ftg = flowtable_create();

    struct flowtable_entry *ftes = calloc(n, sizeof(*ftes));
    assert(ftes);

    int i;
    struct flowtable_key P;

    /* Add entries */
    for (i = 0; i < n; i++) {
        P = make_generic_key(i);
        assert(flowtable_match(ftg, &P) == NULL);
        ftes[i] = make_generic_flow(i, i, 1000);
        flowtable_insert(ftg, &ftes[i]);
        assert(flowtable_match(ftg, &P) == &ftes[i]);
    }

    /* Match on overfull table */
    for (i = 0; i < n; i++) {
        P = make_generic_key(i);
        assert(flowtable_match(ftg, &P) == &ftes[i]);
    }

    /* Remove entries */
    for (i = 0; i < n; i++) {
        P = make_generic_key(i);
        assert(flowtable_match(ftg, &P) == &ftes[i]);
        flowtable_remove(ftg, &ftes[i]);
        assert(flowtable_match(ftg, &P) == NULL);
    }

    flowtable_destroy(ftg);

    free(ftes);
}

int aim_main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    test_basic();
    test_wildcard_priority();
    test_collisions();

    test_flowtable_generic_basic();
    test_flowtable_generic_wildcard_priority();
    test_flowtable_generic_collisions();

    return 0;
}
