/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLS context lifecycle: creation, identity loading, and cleanup.
 */

#include "qshield/tls.h"
#include "qshield/crypto.h"
#include <stdlib.h>
#include <string.h>

qshield_tls_ctx_t *qshield_tls_ctx_new(qshield_tls_role_t role)
{
    qshield_tls_ctx_t *ctx = calloc(1, sizeof(qshield_tls_ctx_t));
    if (!ctx) return NULL;

    ctx->role  = role;
    ctx->state = QSHIELD_TLS_STATE_INIT;
    ctx->shared_secret_ready = 0;
    ctx->identity_loaded = 0;
    ctx->negotiated_group = QSHIELD_GROUP_X25519_KYBER768;
    ctx->negotiated_sig   = QSHIELD_SIG_DILITHIUM3;

    return ctx;
}

void qshield_tls_ctx_free(qshield_tls_ctx_t *ctx)
{
    if (!ctx) return;

    /* Securely erase all key material */
    qshield_secure_zero(&ctx->local_hybrid_kp, sizeof(ctx->local_hybrid_kp));
    qshield_secure_zero(ctx->shared_secret, sizeof(ctx->shared_secret));
    qshield_secure_zero(&ctx->identity_kp, sizeof(ctx->identity_kp));

    free(ctx);
}

int qshield_tls_load_identity(qshield_tls_ctx_t *ctx,
                              const uint8_t *pk,
                              const uint8_t *sk)
{
    if (!ctx || !pk || !sk) return -1;

    memcpy(ctx->identity_kp.public_key, pk, QSHIELD_DILITHIUM_PUBLIC_KEY_LEN);
    memcpy(ctx->identity_kp.secret_key, sk, QSHIELD_DILITHIUM_SECRET_KEY_LEN);
    ctx->identity_loaded = 1;

    return 0;
}
