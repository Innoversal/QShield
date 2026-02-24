/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * QShield Crypto — Wrappers around NIST PQC primitives.
 *
 * Provides a stable API over liboqs for:
 *   - CRYSTALS-Kyber 768  (KEM, FIPS 203)
 *   - CRYSTALS-Dilithium 3 (Signatures, FIPS 204)
 */

#ifndef QSHIELD_CRYPTO_H
#define QSHIELD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Kyber-768 Key Encapsulation                                       */
/* ------------------------------------------------------------------ */

/** Sizes (bytes) for Kyber-768 */
#define QSHIELD_KYBER_PUBLIC_KEY_LEN  1184
#define QSHIELD_KYBER_SECRET_KEY_LEN  2400
#define QSHIELD_KYBER_CIPHERTEXT_LEN  1088
#define QSHIELD_KYBER_SHARED_SECRET_LEN 32

/** Kyber-768 keypair. */
typedef struct {
    uint8_t public_key[QSHIELD_KYBER_PUBLIC_KEY_LEN];
    uint8_t secret_key[QSHIELD_KYBER_SECRET_KEY_LEN];
} qshield_kyber_keypair_t;

/**
 * Generate a Kyber-768 keypair.
 * Returns 0 on success.
 */
int qshield_kyber_keygen(qshield_kyber_keypair_t *kp);

/**
 * Encapsulate: produce a ciphertext and shared secret from a public key.
 * @param ciphertext   Output buffer (QSHIELD_KYBER_CIPHERTEXT_LEN bytes)
 * @param shared_secret Output buffer (QSHIELD_KYBER_SHARED_SECRET_LEN bytes)
 * @param public_key   Peer's public key (QSHIELD_KYBER_PUBLIC_KEY_LEN bytes)
 * Returns 0 on success.
 */
int qshield_kyber_encaps(uint8_t *ciphertext,
                         uint8_t *shared_secret,
                         const uint8_t *public_key);

/**
 * Decapsulate: recover the shared secret from a ciphertext using the secret key.
 * @param shared_secret Output buffer (QSHIELD_KYBER_SHARED_SECRET_LEN bytes)
 * @param ciphertext    Ciphertext (QSHIELD_KYBER_CIPHERTEXT_LEN bytes)
 * @param secret_key    Own secret key (QSHIELD_KYBER_SECRET_KEY_LEN bytes)
 * Returns 0 on success.
 */
int qshield_kyber_decaps(uint8_t *shared_secret,
                         const uint8_t *ciphertext,
                         const uint8_t *secret_key);

/* ------------------------------------------------------------------ */
/*  Dilithium-3 Digital Signatures                                    */
/* ------------------------------------------------------------------ */

/** Sizes (bytes) for Dilithium-3 */
#define QSHIELD_DILITHIUM_PUBLIC_KEY_LEN  1952
#define QSHIELD_DILITHIUM_SECRET_KEY_LEN  4000
#define QSHIELD_DILITHIUM_SIGNATURE_LEN   3293

/** Dilithium-3 keypair. */
typedef struct {
    uint8_t public_key[QSHIELD_DILITHIUM_PUBLIC_KEY_LEN];
    uint8_t secret_key[QSHIELD_DILITHIUM_SECRET_KEY_LEN];
} qshield_dilithium_keypair_t;

/**
 * Generate a Dilithium-3 keypair.
 * Returns 0 on success.
 */
int qshield_dilithium_keygen(qshield_dilithium_keypair_t *kp);

/**
 * Sign a message with Dilithium-3.
 * @param signature     Output buffer (up to QSHIELD_DILITHIUM_SIGNATURE_LEN bytes)
 * @param signature_len Output: actual signature length
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param secret_key    Signer's secret key
 * Returns 0 on success.
 */
int qshield_dilithium_sign(uint8_t *signature,
                           size_t *signature_len,
                           const uint8_t *message,
                           size_t message_len,
                           const uint8_t *secret_key);

/**
 * Verify a Dilithium-3 signature.
 * @param message       Original message
 * @param message_len   Length of message
 * @param signature     Signature to verify
 * @param signature_len Length of signature
 * @param public_key    Signer's public key
 * Returns 0 if the signature is valid, non-zero otherwise.
 */
int qshield_dilithium_verify(const uint8_t *message,
                             size_t message_len,
                             const uint8_t *signature,
                             size_t signature_len,
                             const uint8_t *public_key);

/* ------------------------------------------------------------------ */
/*  Secure memory utilities                                           */
/* ------------------------------------------------------------------ */

/**
 * Securely zero memory (not optimised away by compiler).
 */
void qshield_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QSHIELD_CRYPTO_H */
