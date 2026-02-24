/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid X25519 + Kyber-768 key exchange.
 *
 * The combined shared secret is derived as:
 *   HKDF-SHA256(x25519_ss || kyber_ss, info="qshield hybrid 1.0")
 *
 * This ensures an attacker must break BOTH algorithms.
 */

#include "qshield/hybrid.h"
#include "qshield/crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

static const char HKDF_INFO[] = "qshield hybrid 1.0";

/* ------------------------------------------------------------------ */
/*  Internal: X25519 operations via OpenSSL EVP                       */
/* ------------------------------------------------------------------ */

static int x25519_keygen(uint8_t *pk, uint8_t *sk)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) goto done;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;

    size_t pk_len = QSHIELD_X25519_PUBLIC_KEY_LEN;
    size_t sk_len = QSHIELD_X25519_SECRET_KEY_LEN;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0) goto done;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) goto done;

    ret = 0;
done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int x25519_derive(uint8_t *shared_secret,
                         const uint8_t *own_sk,
                         const uint8_t *peer_pk)
{
    int ret = -1;
    EVP_PKEY *own_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    own_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                            own_sk, QSHIELD_X25519_SECRET_KEY_LEN);
    if (!own_key) goto done;

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                            peer_pk, QSHIELD_X25519_PUBLIC_KEY_LEN);
    if (!peer_key) goto done;

    ctx = EVP_PKEY_CTX_new(own_key, NULL);
    if (!ctx) goto done;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) goto done;

    size_t ss_len = QSHIELD_X25519_SHARED_SECRET_LEN;
    if (EVP_PKEY_derive(ctx, shared_secret, &ss_len) <= 0) goto done;

    ret = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(own_key);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Internal: HKDF to combine classical + PQ secrets                  */
/* ------------------------------------------------------------------ */

static int hkdf_combine(uint8_t *out, size_t out_len,
                        const uint8_t *x25519_ss,
                        const uint8_t *kyber_ss)
{
    int ret = -1;

    /* Concatenate: x25519_ss || kyber_ss */
    uint8_t ikm[QSHIELD_X25519_SHARED_SECRET_LEN + QSHIELD_KYBER_SHARED_SECRET_LEN];
    memcpy(ikm, x25519_ss, QSHIELD_X25519_SHARED_SECRET_LEN);
    memcpy(ikm + QSHIELD_X25519_SHARED_SECRET_LEN, kyber_ss,
           QSHIELD_KYBER_SHARED_SECRET_LEN);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        goto cleanup;
    }

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", ikm, sizeof(ikm));
    params[2] = OSSL_PARAM_construct_octet_string("info",
                    (void *)HKDF_INFO, sizeof(HKDF_INFO) - 1);
    params[3] = OSSL_PARAM_construct_utf8_string("mode", "EXTRACT_AND_EXPAND", 0);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        goto cleanup;
    }

    ret = 0;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

cleanup:
    qshield_secure_zero(ikm, sizeof(ikm));
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

int qshield_hybrid_keygen(qshield_hybrid_keypair_t *kp)
{
    if (!kp) return -1;

    /* Generate X25519 keypair */
    if (x25519_keygen(kp->x25519_public, kp->x25519_secret) != 0) {
        return -1;
    }

    /* Generate Kyber keypair */
    qshield_kyber_keypair_t kyber_kp;
    if (qshield_kyber_keygen(&kyber_kp) != 0) {
        qshield_secure_zero(kp, sizeof(*kp));
        return -1;
    }

    memcpy(kp->kyber_public, kyber_kp.public_key, QSHIELD_KYBER_PUBLIC_KEY_LEN);
    memcpy(kp->kyber_secret, kyber_kp.secret_key, QSHIELD_KYBER_SECRET_KEY_LEN);

    qshield_secure_zero(&kyber_kp, sizeof(kyber_kp));
    return 0;
}

int qshield_hybrid_encaps(uint8_t *ciphertext,
                          uint8_t *shared_secret,
                          const uint8_t *peer_x25519_pk,
                          const uint8_t *peer_kyber_pk)
{
    if (!ciphertext || !shared_secret || !peer_x25519_pk || !peer_kyber_pk) {
        return -1;
    }

    int ret = -1;
    uint8_t ephem_x25519_pk[QSHIELD_X25519_PUBLIC_KEY_LEN];
    uint8_t ephem_x25519_sk[QSHIELD_X25519_SECRET_KEY_LEN];
    uint8_t x25519_ss[QSHIELD_X25519_SHARED_SECRET_LEN];
    uint8_t kyber_ss[QSHIELD_KYBER_SHARED_SECRET_LEN];

    /* Generate ephemeral X25519 keypair */
    if (x25519_keygen(ephem_x25519_pk, ephem_x25519_sk) != 0) {
        goto cleanup;
    }

    /* X25519 key agreement */
    if (x25519_derive(x25519_ss, ephem_x25519_sk, peer_x25519_pk) != 0) {
        goto cleanup;
    }

    /* Kyber encapsulation */
    uint8_t *kyber_ct = ciphertext + QSHIELD_X25519_PUBLIC_KEY_LEN;
    if (qshield_kyber_encaps(kyber_ct, kyber_ss, peer_kyber_pk) != 0) {
        goto cleanup;
    }

    /* Pack ciphertext: ephemeral X25519 pk || Kyber ciphertext */
    memcpy(ciphertext, ephem_x25519_pk, QSHIELD_X25519_PUBLIC_KEY_LEN);

    /* Combine both secrets via HKDF */
    if (hkdf_combine(shared_secret, QSHIELD_HYBRID_SHARED_SECRET_LEN,
                     x25519_ss, kyber_ss) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    qshield_secure_zero(ephem_x25519_sk, sizeof(ephem_x25519_sk));
    qshield_secure_zero(x25519_ss, sizeof(x25519_ss));
    qshield_secure_zero(kyber_ss, sizeof(kyber_ss));
    return ret;
}

int qshield_hybrid_decaps(uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const uint8_t *own_x25519_sk,
                          const uint8_t *own_kyber_sk)
{
    if (!shared_secret || !ciphertext || !own_x25519_sk || !own_kyber_sk) {
        return -1;
    }

    int ret = -1;
    uint8_t x25519_ss[QSHIELD_X25519_SHARED_SECRET_LEN];
    uint8_t kyber_ss[QSHIELD_KYBER_SHARED_SECRET_LEN];

    /* Extract peer's ephemeral X25519 public key from ciphertext */
    const uint8_t *peer_ephem_pk = ciphertext;
    const uint8_t *kyber_ct = ciphertext + QSHIELD_X25519_PUBLIC_KEY_LEN;

    /* X25519 key agreement */
    if (x25519_derive(x25519_ss, own_x25519_sk, peer_ephem_pk) != 0) {
        goto cleanup;
    }

    /* Kyber decapsulation */
    if (qshield_kyber_decaps(kyber_ss, kyber_ct, own_kyber_sk) != 0) {
        goto cleanup;
    }

    /* Combine both secrets via HKDF */
    if (hkdf_combine(shared_secret, QSHIELD_HYBRID_SHARED_SECRET_LEN,
                     x25519_ss, kyber_ss) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    qshield_secure_zero(x25519_ss, sizeof(x25519_ss));
    qshield_secure_zero(kyber_ss, sizeof(kyber_ss));
    return ret;
}
