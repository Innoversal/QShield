/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * CRYSTALS-Kyber 768 KEM wrapper over liboqs.
 * Provides key generation, encapsulation, and decapsulation.
 */

#include "qshield/crypto.h"
#include <oqs/oqs.h>
#include <string.h>

#define KYBER_ALG_NAME OQS_KEM_alg_kyber_768

int qshield_kyber_keygen(qshield_kyber_keypair_t *kp)
{
    if (!kp) {
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (!kem) {
        return -1;
    }

    OQS_STATUS rc = OQS_KEM_keypair(kem, kp->public_key, kp->secret_key);

    OQS_KEM_free(kem);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int qshield_kyber_encaps(uint8_t *ciphertext,
                         uint8_t *shared_secret,
                         const uint8_t *public_key)
{
    if (!ciphertext || !shared_secret || !public_key) {
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (!kem) {
        return -1;
    }

    OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);

    OQS_KEM_free(kem);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}

int qshield_kyber_decaps(uint8_t *shared_secret,
                         const uint8_t *ciphertext,
                         const uint8_t *secret_key)
{
    if (!shared_secret || !ciphertext || !secret_key) {
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(KYBER_ALG_NAME);
    if (!kem) {
        return -1;
    }

    OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);

    OQS_KEM_free(kem);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}
