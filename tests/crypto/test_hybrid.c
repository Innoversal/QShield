/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for hybrid X25519+Kyber key exchange.
 */

#include "qshield/qshield.h"
#include "qshield/hybrid.h"
#include "test_helpers.h"
#include <string.h>

static void test_hybrid_keygen(void)
{
    qshield_hybrid_keypair_t kp;
    memset(&kp, 0, sizeof(kp));

    int rc = qshield_hybrid_keygen(&kp);
    TEST_ASSERT_EQ(rc, 0, "keygen returns 0");

    uint8_t zeros_x[QSHIELD_X25519_PUBLIC_KEY_LEN];
    memset(zeros_x, 0, sizeof(zeros_x));
    TEST_ASSERT_MEM_NEQ(kp.x25519_public, zeros_x, sizeof(zeros_x),
                        "X25519 public key is non-zero");

    uint8_t zeros_k[QSHIELD_KYBER_PUBLIC_KEY_LEN];
    memset(zeros_k, 0, sizeof(zeros_k));
    TEST_ASSERT_MEM_NEQ(kp.kyber_public, zeros_k, sizeof(zeros_k),
                        "Kyber public key is non-zero");
}

static void test_hybrid_encaps_decaps(void)
{
    /* Server generates a static keypair */
    qshield_hybrid_keypair_t server_kp;
    int rc = qshield_hybrid_keygen(&server_kp);
    TEST_ASSERT_EQ(rc, 0, "server keygen ok");

    /* Client encapsulates to server */
    uint8_t ct[QSHIELD_HYBRID_CIPHERTEXT_LEN];
    uint8_t client_ss[QSHIELD_HYBRID_SHARED_SECRET_LEN];

    rc = qshield_hybrid_encaps(ct, client_ss,
                               server_kp.x25519_public,
                               server_kp.kyber_public);
    TEST_ASSERT_EQ(rc, 0, "encaps returns 0");

    /* Server decapsulates */
    uint8_t server_ss[QSHIELD_HYBRID_SHARED_SECRET_LEN];
    rc = qshield_hybrid_decaps(server_ss, ct,
                               server_kp.x25519_secret,
                               server_kp.kyber_secret);
    TEST_ASSERT_EQ(rc, 0, "decaps returns 0");

    /* Both sides should derive the same shared secret */
    TEST_ASSERT_MEM_EQ(client_ss, server_ss, QSHIELD_HYBRID_SHARED_SECRET_LEN,
                       "hybrid shared secrets match");
}

static void test_hybrid_different_keys_differ(void)
{
    qshield_hybrid_keypair_t kp1, kp2;
    qshield_hybrid_keygen(&kp1);
    qshield_hybrid_keygen(&kp2);

    uint8_t ct[QSHIELD_HYBRID_CIPHERTEXT_LEN];
    uint8_t ss_enc[QSHIELD_HYBRID_SHARED_SECRET_LEN];
    uint8_t ss_dec[QSHIELD_HYBRID_SHARED_SECRET_LEN];

    /* Encapsulate to kp1 */
    qshield_hybrid_encaps(ct, ss_enc,
                          kp1.x25519_public, kp1.kyber_public);

    /* Try decapsulating with kp2's keys — should produce different secret */
    qshield_hybrid_decaps(ss_dec, ct,
                          kp2.x25519_secret, kp2.kyber_secret);

    TEST_ASSERT_MEM_NEQ(ss_enc, ss_dec, QSHIELD_HYBRID_SHARED_SECRET_LEN,
                        "wrong keys produce different shared secret");
}

static void test_hybrid_null_args(void)
{
    TEST_ASSERT_EQ(qshield_hybrid_keygen(NULL), -1,
                   "keygen rejects NULL");
    TEST_ASSERT_EQ(qshield_hybrid_encaps(NULL, NULL, NULL, NULL), -1,
                   "encaps rejects NULL");
    TEST_ASSERT_EQ(qshield_hybrid_decaps(NULL, NULL, NULL, NULL), -1,
                   "decaps rejects NULL");
}

int main(void)
{
    qshield_init();

    printf("=== Hybrid X25519+Kyber Tests ===\n");
    RUN_TEST(test_hybrid_keygen);
    RUN_TEST(test_hybrid_encaps_decaps);
    RUN_TEST(test_hybrid_different_keys_differ);
    RUN_TEST(test_hybrid_null_args);

    qshield_cleanup();
    TEST_SUMMARY();
}
