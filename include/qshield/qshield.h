/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * QShield — Quantum-Safe Security Infrastructure
 * Created by Abu Bokor Siddick, Innoversal (Bangladesh)
 *
 * Top-level public header.
 */

#ifndef QSHIELD_H
#define QSHIELD_H

#include "qshield/version.h"
#include "qshield/crypto.h"
#include "qshield/hybrid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialise the QShield library.
 * Must be called before any other QShield function.
 * Returns 0 on success, non-zero on failure.
 */
int qshield_init(void);

/**
 * Clean up QShield library resources.
 * Call once when finished with QShield.
 */
void qshield_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* QSHIELD_H */
