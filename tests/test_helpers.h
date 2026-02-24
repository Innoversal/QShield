/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal test harness — no external dependencies.
 */

#ifndef QSHIELD_TEST_HELPERS_H
#define QSHIELD_TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                        \
    do {                                                              \
        tests_run++;                                                  \
        if (cond) {                                                   \
            tests_passed++;                                           \
            printf("  PASS: %s\n", msg);                              \
        } else {                                                      \
            tests_failed++;                                           \
            printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
        }                                                             \
    } while (0)

#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) \
    TEST_ASSERT(memcmp((a), (b), (len)) == 0, msg)

#define TEST_ASSERT_MEM_NEQ(a, b, len, msg) \
    TEST_ASSERT(memcmp((a), (b), (len)) != 0, msg)

#define TEST_SUMMARY()                                                         \
    do {                                                                       \
        printf("\n--- %d tests: %d passed, %d failed ---\n",                   \
               tests_run, tests_passed, tests_failed);                         \
        return tests_failed > 0 ? 1 : 0;                                      \
    } while (0)

#define RUN_TEST(fn)                                                           \
    do {                                                                       \
        printf("[%s]\n", #fn);                                                 \
        fn();                                                                  \
    } while (0)

#endif /* QSHIELD_TEST_HELPERS_H */
