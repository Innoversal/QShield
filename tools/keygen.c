/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * qshield-keygen — Generate post-quantum keypairs.
 *
 * Usage:
 *   qshield-keygen kyber     Generate a Kyber-768 keypair
 *   qshield-keygen dilithium Generate a Dilithium-3 keypair
 *   qshield-keygen hybrid    Generate a hybrid X25519+Kyber keypair
 */

#include "qshield/qshield.h"
#include "qshield/crypto.h"
#include "qshield/hybrid.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i > 0 && (i + 1) % 32 == 0 && i + 1 < len) {
            printf("\n  ");
        }
    }
    printf("\n\n");
}

static int cmd_kyber(void)
{
    qshield_kyber_keypair_t kp;
    if (qshield_kyber_keygen(&kp) != 0) {
        fprintf(stderr, "Error: Kyber keygen failed\n");
        return 1;
    }

    printf("=== Kyber-768 Keypair ===\n\n");
    print_hex("Public Key", kp.public_key, QSHIELD_KYBER_PUBLIC_KEY_LEN);
    print_hex("Secret Key", kp.secret_key, QSHIELD_KYBER_SECRET_KEY_LEN);

    qshield_secure_zero(&kp, sizeof(kp));
    return 0;
}

static int cmd_dilithium(void)
{
    qshield_dilithium_keypair_t kp;
    if (qshield_dilithium_keygen(&kp) != 0) {
        fprintf(stderr, "Error: Dilithium keygen failed\n");
        return 1;
    }

    printf("=== Dilithium-3 Keypair ===\n\n");
    print_hex("Public Key", kp.public_key, QSHIELD_DILITHIUM_PUBLIC_KEY_LEN);
    print_hex("Secret Key", kp.secret_key, QSHIELD_DILITHIUM_SECRET_KEY_LEN);

    qshield_secure_zero(&kp, sizeof(kp));
    return 0;
}

static int cmd_hybrid(void)
{
    qshield_hybrid_keypair_t kp;
    if (qshield_hybrid_keygen(&kp) != 0) {
        fprintf(stderr, "Error: Hybrid keygen failed\n");
        return 1;
    }

    printf("=== Hybrid X25519+Kyber Keypair ===\n\n");
    print_hex("X25519 Public Key", kp.x25519_public, QSHIELD_X25519_PUBLIC_KEY_LEN);
    print_hex("X25519 Secret Key", kp.x25519_secret, QSHIELD_X25519_SECRET_KEY_LEN);
    print_hex("Kyber Public Key", kp.kyber_public, QSHIELD_KYBER_PUBLIC_KEY_LEN);
    print_hex("Kyber Secret Key", kp.kyber_secret, QSHIELD_KYBER_SECRET_KEY_LEN);

    qshield_secure_zero(&kp, sizeof(kp));
    return 0;
}

static void usage(void)
{
    printf("QShield Key Generator v%s\n\n", QSHIELD_VERSION_STRING);
    printf("Usage: qshield-keygen <algorithm>\n\n");
    printf("Algorithms:\n");
    printf("  kyber       Generate a Kyber-768 KEM keypair\n");
    printf("  dilithium   Generate a Dilithium-3 signature keypair\n");
    printf("  hybrid      Generate a hybrid X25519+Kyber keypair\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage();
        return 1;
    }

    qshield_init();
    int rc;

    if (strcmp(argv[1], "kyber") == 0) {
        rc = cmd_kyber();
    } else if (strcmp(argv[1], "dilithium") == 0) {
        rc = cmd_dilithium();
    } else if (strcmp(argv[1], "hybrid") == 0) {
        rc = cmd_hybrid();
    } else {
        fprintf(stderr, "Unknown algorithm: %s\n\n", argv[1]);
        usage();
        rc = 1;
    }

    qshield_cleanup();
    return rc;
}
