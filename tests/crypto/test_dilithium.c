/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for Dilithium-3 signature wrapper.
 */

#include "qshield/qshield.h"
#include "qshield/crypto.h"
#include "test_helpers.h"
#include <string.h>

static const uint8_t TEST_MSG[] = "QShield test message for Dilithium signatures";

static void test_dilithium_keygen(void)
{
    qshield_dilithium_keypair_t kp;
    memset(&kp, 0, sizeof(kp));

    int rc = qshield_dilithium_keygen(&kp);
    TEST_ASSERT_EQ(rc, 0, "keygen returns 0");

    uint8_t zeros[QSHIELD_DILITHIUM_PUBLIC_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));
    TEST_ASSERT_MEM_NEQ(kp.public_key, zeros, sizeof(zeros),
                        "public key is non-zero");
}

static void test_dilithium_sign_verify(void)
{
    qshield_dilithium_keypair_t kp;
    qshield_dilithium_keygen(&kp);

    uint8_t sig[QSHIELD_DILITHIUM_SIGNATURE_LEN];
    size_t sig_len = 0;

    int rc = qshield_dilithium_sign(sig, &sig_len,
                                     TEST_MSG, sizeof(TEST_MSG),
                                     kp.secret_key);
    TEST_ASSERT_EQ(rc, 0, "sign returns 0");
    TEST_ASSERT(sig_len > 0, "signature length > 0");
    TEST_ASSERT(sig_len <= QSHIELD_DILITHIUM_SIGNATURE_LEN,
                "signature length within bounds");

    rc = qshield_dilithium_verify(TEST_MSG, sizeof(TEST_MSG),
                                   sig, sig_len, kp.public_key);
    TEST_ASSERT_EQ(rc, 0, "valid signature verifies");
}

static void test_dilithium_wrong_key_fails(void)
{
    qshield_dilithium_keypair_t kp1, kp2;
    qshield_dilithium_keygen(&kp1);
    qshield_dilithium_keygen(&kp2);

    uint8_t sig[QSHIELD_DILITHIUM_SIGNATURE_LEN];
    size_t sig_len = 0;

    qshield_dilithium_sign(sig, &sig_len,
                           TEST_MSG, sizeof(TEST_MSG),
                           kp1.secret_key);

    /* Verify with wrong public key */
    int rc = qshield_dilithium_verify(TEST_MSG, sizeof(TEST_MSG),
                                       sig, sig_len, kp2.public_key);
    TEST_ASSERT(rc != 0, "wrong key rejects signature");
}

static void test_dilithium_tampered_msg_fails(void)
{
    qshield_dilithium_keypair_t kp;
    qshield_dilithium_keygen(&kp);

    uint8_t sig[QSHIELD_DILITHIUM_SIGNATURE_LEN];
    size_t sig_len = 0;

    qshield_dilithium_sign(sig, &sig_len,
                           TEST_MSG, sizeof(TEST_MSG),
                           kp.secret_key);

    /* Tamper with the message */
    uint8_t bad_msg[] = "Tampered message";
    int rc = qshield_dilithium_verify(bad_msg, sizeof(bad_msg),
                                       sig, sig_len, kp.public_key);
    TEST_ASSERT(rc != 0, "tampered message rejects signature");
}

static void test_dilithium_null_args(void)
{
    TEST_ASSERT_EQ(qshield_dilithium_keygen(NULL), -1,
                   "keygen rejects NULL");
    TEST_ASSERT_EQ(qshield_dilithium_sign(NULL, NULL, NULL, 0, NULL), -1,
                   "sign rejects NULL");
    TEST_ASSERT_EQ(qshield_dilithium_verify(NULL, 0, NULL, 0, NULL), -1,
                   "verify rejects NULL");
}

int main(void)
{
    qshield_init();

    printf("=== Dilithium-3 Tests ===\n");
    RUN_TEST(test_dilithium_keygen);
    RUN_TEST(test_dilithium_sign_verify);
    RUN_TEST(test_dilithium_wrong_key_fails);
    RUN_TEST(test_dilithium_tampered_msg_fails);
    RUN_TEST(test_dilithium_null_args);

    qshield_cleanup();
    TEST_SUMMARY();
}
