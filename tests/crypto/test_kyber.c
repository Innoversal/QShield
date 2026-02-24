/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for Kyber-768 KEM wrapper.
 */

#include "qshield/qshield.h"
#include "qshield/crypto.h"
#include "test_helpers.h"
#include <string.h>

static void test_kyber_keygen(void)
{
    qshield_kyber_keypair_t kp;
    memset(&kp, 0, sizeof(kp));

    int rc = qshield_kyber_keygen(&kp);
    TEST_ASSERT_EQ(rc, 0, "keygen returns 0");

    /* Public key should not be all zeros */
    uint8_t zeros[QSHIELD_KYBER_PUBLIC_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));
    TEST_ASSERT_MEM_NEQ(kp.public_key, zeros, sizeof(zeros),
                        "public key is non-zero");
}

static void test_kyber_encaps_decaps(void)
{
    qshield_kyber_keypair_t kp;
    int rc = qshield_kyber_keygen(&kp);
    TEST_ASSERT_EQ(rc, 0, "keygen succeeds");

    uint8_t ct[QSHIELD_KYBER_CIPHERTEXT_LEN];
    uint8_t ss_enc[QSHIELD_KYBER_SHARED_SECRET_LEN];
    uint8_t ss_dec[QSHIELD_KYBER_SHARED_SECRET_LEN];

    rc = qshield_kyber_encaps(ct, ss_enc, kp.public_key);
    TEST_ASSERT_EQ(rc, 0, "encaps returns 0");

    rc = qshield_kyber_decaps(ss_dec, ct, kp.secret_key);
    TEST_ASSERT_EQ(rc, 0, "decaps returns 0");

    TEST_ASSERT_MEM_EQ(ss_enc, ss_dec, QSHIELD_KYBER_SHARED_SECRET_LEN,
                       "shared secrets match");
}

static void test_kyber_wrong_key_fails(void)
{
    qshield_kyber_keypair_t kp1, kp2;
    qshield_kyber_keygen(&kp1);
    qshield_kyber_keygen(&kp2);

    uint8_t ct[QSHIELD_KYBER_CIPHERTEXT_LEN];
    uint8_t ss_enc[QSHIELD_KYBER_SHARED_SECRET_LEN];
    uint8_t ss_dec[QSHIELD_KYBER_SHARED_SECRET_LEN];

    qshield_kyber_encaps(ct, ss_enc, kp1.public_key);
    qshield_kyber_decaps(ss_dec, ct, kp2.secret_key);  /* Wrong key */

    TEST_ASSERT_MEM_NEQ(ss_enc, ss_dec, QSHIELD_KYBER_SHARED_SECRET_LEN,
                        "wrong key produces different shared secret");
}

static void test_kyber_null_args(void)
{
    TEST_ASSERT_EQ(qshield_kyber_keygen(NULL), -1,
                   "keygen rejects NULL");
    TEST_ASSERT_EQ(qshield_kyber_encaps(NULL, NULL, NULL), -1,
                   "encaps rejects NULL");
    TEST_ASSERT_EQ(qshield_kyber_decaps(NULL, NULL, NULL), -1,
                   "decaps rejects NULL");
}

int main(void)
{
    qshield_init();

    printf("=== Kyber-768 Tests ===\n");
    RUN_TEST(test_kyber_keygen);
    RUN_TEST(test_kyber_encaps_decaps);
    RUN_TEST(test_kyber_wrong_key_fails);
    RUN_TEST(test_kyber_null_args);

    qshield_cleanup();
    TEST_SUMMARY();
}
