/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * QShield Hybrid Key Exchange — X25519 + Kyber-768
 *
 * Combines classical ECDH (X25519) with post-quantum KEM (Kyber-768)
 * into a single hybrid shared secret:
 *
 *   shared_secret = HKDF-SHA3-256(x25519_ss || kyber_ss, "qshield hybrid 1.0")
 *
 * Breaking the hybrid requires breaking BOTH X25519 and Kyber.
 */

#ifndef QSHIELD_HYBRID_H
#define QSHIELD_HYBRID_H

#include <stddef.h>
#include <stdint.h>
#include "qshield/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** X25519 key sizes */
#define QSHIELD_X25519_PUBLIC_KEY_LEN  32
#define QSHIELD_X25519_SECRET_KEY_LEN  32
#define QSHIELD_X25519_SHARED_SECRET_LEN 32

/** Hybrid combined sizes */
#define QSHIELD_HYBRID_PUBLIC_KEY_LEN  \
    (QSHIELD_X25519_PUBLIC_KEY_LEN + QSHIELD_KYBER_PUBLIC_KEY_LEN)

#define QSHIELD_HYBRID_SECRET_KEY_LEN  \
    (QSHIELD_X25519_SECRET_KEY_LEN + QSHIELD_KYBER_SECRET_KEY_LEN)

/** Final derived shared secret (32 bytes from HKDF) */
#define QSHIELD_HYBRID_SHARED_SECRET_LEN 32

/** Hybrid ciphertext: X25519 ephemeral public + Kyber ciphertext */
#define QSHIELD_HYBRID_CIPHERTEXT_LEN \
    (QSHIELD_X25519_PUBLIC_KEY_LEN + QSHIELD_KYBER_CIPHERTEXT_LEN)

/** Hybrid keypair containing both X25519 and Kyber components. */
typedef struct {
    uint8_t x25519_public[QSHIELD_X25519_PUBLIC_KEY_LEN];
    uint8_t x25519_secret[QSHIELD_X25519_SECRET_KEY_LEN];
    uint8_t kyber_public[QSHIELD_KYBER_PUBLIC_KEY_LEN];
    uint8_t kyber_secret[QSHIELD_KYBER_SECRET_KEY_LEN];
} qshield_hybrid_keypair_t;

/**
 * Generate a hybrid X25519+Kyber keypair.
 * Returns 0 on success.
 */
int qshield_hybrid_keygen(qshield_hybrid_keypair_t *kp);

/**
 * Initiator: create a hybrid key exchange message (encapsulate).
 *
 * Given a peer's hybrid public key, produce:
 *   - ciphertext (X25519 ephemeral public + Kyber ciphertext)
 *   - shared_secret (32-byte derived key)
 *
 * @param ciphertext     Output (QSHIELD_HYBRID_CIPHERTEXT_LEN bytes)
 * @param shared_secret  Output (QSHIELD_HYBRID_SHARED_SECRET_LEN bytes)
 * @param peer_x25519_pk Peer's X25519 public key
 * @param peer_kyber_pk  Peer's Kyber public key
 * Returns 0 on success.
 */
int qshield_hybrid_encaps(uint8_t *ciphertext,
                          uint8_t *shared_secret,
                          const uint8_t *peer_x25519_pk,
                          const uint8_t *peer_kyber_pk);

/**
 * Responder: process a hybrid key exchange message (decapsulate).
 *
 * Given own secret keys and a ciphertext, recover the shared secret.
 *
 * @param shared_secret  Output (QSHIELD_HYBRID_SHARED_SECRET_LEN bytes)
 * @param ciphertext     Input (QSHIELD_HYBRID_CIPHERTEXT_LEN bytes)
 * @param own_x25519_sk  Own X25519 secret key
 * @param own_kyber_sk   Own Kyber secret key
 * Returns 0 on success.
 */
int qshield_hybrid_decaps(uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const uint8_t *own_x25519_sk,
                          const uint8_t *own_kyber_sk);

#ifdef __cplusplus
}
#endif

#endif /* QSHIELD_HYBRID_H */
