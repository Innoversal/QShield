/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * QShield TLS — Hybrid quantum-safe TLS 1.3 handshake.
 *
 * This module defines the TLS handshake state machine and message
 * structures for the hybrid X25519+Kyber key exchange and Dilithium
 * certificate authentication.
 */

#ifndef QSHIELD_TLS_H
#define QSHIELD_TLS_H

#include <stddef.h>
#include <stdint.h>
#include "qshield/hybrid.h"
#include "qshield/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  TLS handshake state machine                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    QSHIELD_TLS_STATE_INIT = 0,
    QSHIELD_TLS_STATE_CLIENT_HELLO_SENT,
    QSHIELD_TLS_STATE_SERVER_HELLO_RECEIVED,
    QSHIELD_TLS_STATE_SERVER_HELLO_SENT,
    QSHIELD_TLS_STATE_CLIENT_HELLO_RECEIVED,
    QSHIELD_TLS_STATE_HANDSHAKE_COMPLETE,
    QSHIELD_TLS_STATE_ERROR
} qshield_tls_state_t;

typedef enum {
    QSHIELD_TLS_ROLE_CLIENT,
    QSHIELD_TLS_ROLE_SERVER
} qshield_tls_role_t;

/* ------------------------------------------------------------------ */
/*  Supported groups / signature algorithms                           */
/* ------------------------------------------------------------------ */

typedef enum {
    QSHIELD_GROUP_X25519_KYBER768 = 0x6399,  /* Hybrid group ID */
    QSHIELD_GROUP_X25519          = 0x001D    /* Classical fallback */
} qshield_named_group_t;

typedef enum {
    QSHIELD_SIG_DILITHIUM3 = 0x0907,  /* PQ signature */
    QSHIELD_SIG_ECDSA_P256 = 0x0403   /* Classical fallback */
} qshield_sig_algorithm_t;

/* ------------------------------------------------------------------ */
/*  TLS context                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    qshield_tls_role_t   role;
    qshield_tls_state_t  state;

    /* Hybrid key exchange state */
    qshield_hybrid_keypair_t  local_hybrid_kp;
    uint8_t                   shared_secret[QSHIELD_HYBRID_SHARED_SECRET_LEN];
    int                       shared_secret_ready;

    /* Dilithium identity for authentication */
    qshield_dilithium_keypair_t identity_kp;
    int                         identity_loaded;

    /* Negotiated parameters */
    qshield_named_group_t    negotiated_group;
    qshield_sig_algorithm_t  negotiated_sig;
} qshield_tls_ctx_t;

/**
 * Create and initialise a new TLS context.
 * @param role  QSHIELD_TLS_ROLE_CLIENT or QSHIELD_TLS_ROLE_SERVER
 * Returns NULL on failure.
 */
qshield_tls_ctx_t *qshield_tls_ctx_new(qshield_tls_role_t role);

/**
 * Free a TLS context and securely erase keys.
 */
void qshield_tls_ctx_free(qshield_tls_ctx_t *ctx);

/**
 * Load a Dilithium identity keypair for TLS authentication.
 * @param ctx  TLS context
 * @param pk   Dilithium public key
 * @param sk   Dilithium secret key
 * Returns 0 on success.
 */
int qshield_tls_load_identity(qshield_tls_ctx_t *ctx,
                              const uint8_t *pk,
                              const uint8_t *sk);

/* ------------------------------------------------------------------ */
/*  Handshake messages                                                */
/* ------------------------------------------------------------------ */

/**
 * Client: generate a ClientHello message containing the hybrid key share.
 * @param ctx     TLS context (role must be CLIENT)
 * @param out     Output buffer for the serialised message
 * @param out_len In: buffer size; Out: bytes written
 * Returns 0 on success.
 */
int qshield_tls_client_hello(qshield_tls_ctx_t *ctx,
                             uint8_t *out, size_t *out_len);

/**
 * Server: process a ClientHello and generate a ServerHello response.
 * @param ctx           TLS context (role must be SERVER)
 * @param client_hello  ClientHello message bytes
 * @param ch_len        Length of ClientHello
 * @param out           Output buffer for ServerHello
 * @param out_len       In: buffer size; Out: bytes written
 * Returns 0 on success.
 */
int qshield_tls_server_hello(qshield_tls_ctx_t *ctx,
                             const uint8_t *client_hello, size_t ch_len,
                             uint8_t *out, size_t *out_len);

/**
 * Client: process a ServerHello and complete key exchange.
 * @param ctx          TLS context
 * @param server_hello ServerHello message bytes
 * @param sh_len       Length of ServerHello
 * Returns 0 on success; shared_secret is then available in ctx.
 */
int qshield_tls_process_server_hello(qshield_tls_ctx_t *ctx,
                                     const uint8_t *server_hello,
                                     size_t sh_len);

#ifdef __cplusplus
}
#endif

#endif /* QSHIELD_TLS_H */
