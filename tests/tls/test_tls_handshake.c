/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration test: full TLS handshake between client and server.
 */

#include "qshield/qshield.h"
#include "qshield/tls.h"
#include "test_helpers.h"
#include <string.h>

static void test_full_handshake(void)
{
    /* Create client and server contexts */
    qshield_tls_ctx_t *client = qshield_tls_ctx_new(QSHIELD_TLS_ROLE_CLIENT);
    qshield_tls_ctx_t *server = qshield_tls_ctx_new(QSHIELD_TLS_ROLE_SERVER);
    TEST_ASSERT(client != NULL, "client context created");
    TEST_ASSERT(server != NULL, "server context created");

    /* Step 1: Client generates ClientHello */
    uint8_t ch_buf[4096];
    size_t ch_len = sizeof(ch_buf);
    int rc = qshield_tls_client_hello(client, ch_buf, &ch_len);
    TEST_ASSERT_EQ(rc, 0, "ClientHello generated");
    TEST_ASSERT(ch_len > 0, "ClientHello has content");

    /* Step 2: Server processes ClientHello and generates ServerHello */
    uint8_t sh_buf[4096];
    size_t sh_len = sizeof(sh_buf);
    rc = qshield_tls_server_hello(server, ch_buf, ch_len, sh_buf, &sh_len);
    TEST_ASSERT_EQ(rc, 0, "ServerHello generated");
    TEST_ASSERT(sh_len > 0, "ServerHello has content");
    TEST_ASSERT_EQ(server->shared_secret_ready, 1,
                   "server has shared secret");

    /* Step 3: Client processes ServerHello */
    rc = qshield_tls_process_server_hello(client, sh_buf, sh_len);
    TEST_ASSERT_EQ(rc, 0, "client processes ServerHello");
    TEST_ASSERT_EQ(client->shared_secret_ready, 1,
                   "client has shared secret");

    /* Verify: both sides derived the same shared secret */
    TEST_ASSERT_MEM_EQ(client->shared_secret, server->shared_secret,
                       QSHIELD_HYBRID_SHARED_SECRET_LEN,
                       "client and server shared secrets match");

    /* Verify: handshake reached expected state */
    TEST_ASSERT_EQ(client->state, QSHIELD_TLS_STATE_HANDSHAKE_COMPLETE,
                   "client state is HANDSHAKE_COMPLETE");

    qshield_tls_ctx_free(client);
    qshield_tls_ctx_free(server);
}

static void test_ctx_lifecycle(void)
{
    qshield_tls_ctx_t *ctx = qshield_tls_ctx_new(QSHIELD_TLS_ROLE_CLIENT);
    TEST_ASSERT(ctx != NULL, "context allocated");
    TEST_ASSERT_EQ(ctx->state, QSHIELD_TLS_STATE_INIT, "initial state is INIT");
    TEST_ASSERT_EQ(ctx->role, QSHIELD_TLS_ROLE_CLIENT, "role is CLIENT");

    /* Load identity */
    qshield_dilithium_keypair_t id_kp;
    qshield_dilithium_keygen(&id_kp);
    int rc = qshield_tls_load_identity(ctx, id_kp.public_key, id_kp.secret_key);
    TEST_ASSERT_EQ(rc, 0, "load identity succeeds");
    TEST_ASSERT_EQ(ctx->identity_loaded, 1, "identity is loaded");

    qshield_tls_ctx_free(ctx);
    /* No crash = success */
    TEST_ASSERT(1, "ctx_free does not crash");
}

static void test_wrong_role_rejected(void)
{
    qshield_tls_ctx_t *server = qshield_tls_ctx_new(QSHIELD_TLS_ROLE_SERVER);

    uint8_t buf[4096];
    size_t len = sizeof(buf);

    /* Server should not be able to generate ClientHello */
    int rc = qshield_tls_client_hello(server, buf, &len);
    TEST_ASSERT(rc != 0, "server cannot generate ClientHello");

    qshield_tls_ctx_free(server);
}

int main(void)
{
    qshield_init();

    printf("=== TLS Handshake Tests ===\n");
    RUN_TEST(test_full_handshake);
    RUN_TEST(test_ctx_lifecycle);
    RUN_TEST(test_wrong_role_rejected);

    qshield_cleanup();
    TEST_SUMMARY();
}
