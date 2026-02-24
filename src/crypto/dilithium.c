/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * CRYSTALS-Dilithium 3 signature wrapper over liboqs.
 * Provides key generation, signing, and verification.
 */

#include "qshield/crypto.h"
#include <oqs/oqs.h>
#include <string.h>

#define DILITHIUM_ALG_NAME OQS_SIG_alg_dilithium_3

int qshield_dilithium_keygen(qshield_dilithium_keypair_t *kp)
{
    if (!kp) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG_NAME);
    if (!sig) {
        return -1;
    }

    OQS_STATUS rc = OQS_SIG_keypair(sig, kp->public_key, kp->secret_key);

    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int qshield_dilithium_sign(uint8_t *signature,
                           size_t *signature_len,
                           const uint8_t *message,
                           size_t message_len,
                           const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG_NAME);
    if (!sig) {
        return -1;
    }

    OQS_STATUS rc = OQS_SIG_sign(sig, signature, signature_len,
                                  message, message_len, secret_key);

    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int qshield_dilithium_verify(const uint8_t *message,
                             size_t message_len,
                             const uint8_t *signature,
                             size_t signature_len,
                             const uint8_t *public_key)
{
    if (!message || !signature || !public_key) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG_NAME);
    if (!sig) {
        return -1;
    }

    OQS_STATUS rc = OQS_SIG_verify(sig, message, message_len,
                                    signature, signature_len, public_key);

    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}
