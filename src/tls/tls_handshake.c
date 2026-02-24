/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLS 1.3 hybrid handshake message generation and processing.
 *
 * Wire format (simplified for Phase 1):
 *
 *   ClientHello:
 *     [2 bytes] named_group (0x6399 = X25519Kyber768)
 *     [2 bytes] sig_algorithm (0x0907 = Dilithium3)
 *     [32 bytes] X25519 public key
 *     [1184 bytes] Kyber public key
 *
 *   ServerHello:
 *     [2 bytes] named_group
 *     [2 bytes] sig_algorithm
 *     [32 bytes] X25519 ephemeral public key
 *     [1088 bytes] Kyber ciphertext
 */

#include "qshield/tls.h"
#include "qshield/crypto.h"
#include <string.h>

/* Minimum buffer sizes */
#define CLIENT_HELLO_LEN (2 + 2 + QSHIELD_X25519_PUBLIC_KEY_LEN + QSHIELD_KYBER_PUBLIC_KEY_LEN)
#define SERVER_HELLO_LEN (2 + 2 + QSHIELD_HYBRID_CIPHERTEXT_LEN)

static void write_u16(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xFF);
}

static uint16_t read_u16(const uint8_t *buf)
{
    return (uint16_t)((uint16_t)buf[0] << 8 | (uint16_t)buf[1]);
}

int qshield_tls_client_hello(qshield_tls_ctx_t *ctx,
                             uint8_t *out, size_t *out_len)
{
    if (!ctx || !out || !out_len) return -1;
    if (ctx->role != QSHIELD_TLS_ROLE_CLIENT) return -1;
    if (ctx->state != QSHIELD_TLS_STATE_INIT) return -1;
    if (*out_len < CLIENT_HELLO_LEN) return -1;

    /* Generate our hybrid keypair */
    if (qshield_hybrid_keygen(&ctx->local_hybrid_kp) != 0) {
        ctx->state = QSHIELD_TLS_STATE_ERROR;
        return -1;
    }

    uint8_t *p = out;

    /* Named group */
    write_u16(p, (uint16_t)QSHIELD_GROUP_X25519_KYBER768);
    p += 2;

    /* Signature algorithm */
    write_u16(p, (uint16_t)QSHIELD_SIG_DILITHIUM3);
    p += 2;

    /* X25519 public key */
    memcpy(p, ctx->local_hybrid_kp.x25519_public, QSHIELD_X25519_PUBLIC_KEY_LEN);
    p += QSHIELD_X25519_PUBLIC_KEY_LEN;

    /* Kyber public key */
    memcpy(p, ctx->local_hybrid_kp.kyber_public, QSHIELD_KYBER_PUBLIC_KEY_LEN);
    p += QSHIELD_KYBER_PUBLIC_KEY_LEN;

    *out_len = CLIENT_HELLO_LEN;
    ctx->state = QSHIELD_TLS_STATE_CLIENT_HELLO_SENT;
    return 0;
}

int qshield_tls_server_hello(qshield_tls_ctx_t *ctx,
                             const uint8_t *client_hello, size_t ch_len,
                             uint8_t *out, size_t *out_len)
{
    if (!ctx || !client_hello || !out || !out_len) return -1;
    if (ctx->role != QSHIELD_TLS_ROLE_SERVER) return -1;
    if (ctx->state != QSHIELD_TLS_STATE_INIT) return -1;
    if (ch_len < CLIENT_HELLO_LEN) return -1;
    if (*out_len < SERVER_HELLO_LEN) return -1;

    const uint8_t *p = client_hello;

    /* Parse named group */
    uint16_t group = read_u16(p);
    p += 2;
    if (group != QSHIELD_GROUP_X25519_KYBER768) {
        ctx->state = QSHIELD_TLS_STATE_ERROR;
        return -1;  /* Unsupported group */
    }

    /* Parse sig algorithm */
    uint16_t sig_alg = read_u16(p);
    p += 2;

    ctx->negotiated_group = (qshield_named_group_t)group;
    ctx->negotiated_sig   = (qshield_sig_algorithm_t)sig_alg;

    /* Extract client's X25519 public key */
    const uint8_t *client_x25519_pk = p;
    p += QSHIELD_X25519_PUBLIC_KEY_LEN;

    /* Extract client's Kyber public key */
    const uint8_t *client_kyber_pk = p;

    /* Perform hybrid encapsulation (server -> client) */
    uint8_t hybrid_ct[QSHIELD_HYBRID_CIPHERTEXT_LEN];
    if (qshield_hybrid_encaps(hybrid_ct, ctx->shared_secret,
                              client_x25519_pk, client_kyber_pk) != 0) {
        ctx->state = QSHIELD_TLS_STATE_ERROR;
        return -1;
    }
    ctx->shared_secret_ready = 1;

    /* Build ServerHello */
    uint8_t *op = out;
    write_u16(op, (uint16_t)ctx->negotiated_group);
    op += 2;
    write_u16(op, (uint16_t)ctx->negotiated_sig);
    op += 2;
    memcpy(op, hybrid_ct, QSHIELD_HYBRID_CIPHERTEXT_LEN);

    *out_len = SERVER_HELLO_LEN;
    ctx->state = QSHIELD_TLS_STATE_SERVER_HELLO_SENT;
    return 0;
}

int qshield_tls_process_server_hello(qshield_tls_ctx_t *ctx,
                                     const uint8_t *server_hello,
                                     size_t sh_len)
{
    if (!ctx || !server_hello) return -1;
    if (ctx->role != QSHIELD_TLS_ROLE_CLIENT) return -1;
    if (ctx->state != QSHIELD_TLS_STATE_CLIENT_HELLO_SENT) return -1;
    if (sh_len < SERVER_HELLO_LEN) return -1;

    const uint8_t *p = server_hello;

    /* Parse negotiated parameters */
    ctx->negotiated_group = (qshield_named_group_t)read_u16(p);
    p += 2;
    ctx->negotiated_sig = (qshield_sig_algorithm_t)read_u16(p);
    p += 2;

    /* Hybrid decapsulation: recover shared secret */
    const uint8_t *hybrid_ct = p;
    if (qshield_hybrid_decaps(ctx->shared_secret, hybrid_ct,
                              ctx->local_hybrid_kp.x25519_secret,
                              ctx->local_hybrid_kp.kyber_secret) != 0) {
        ctx->state = QSHIELD_TLS_STATE_ERROR;
        return -1;
    }

    ctx->shared_secret_ready = 1;
    ctx->state = QSHIELD_TLS_STATE_HANDSHAKE_COMPLETE;
    return 0;
}
