/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Secure memory utilities.
 */

#include "qshield/crypto.h"
#include <string.h>

/*
 * Volatile function pointer prevents the compiler from
 * optimising away the memset call.
 */
static void *(*const volatile memset_func)(void *, int, size_t) = memset;

void qshield_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        memset_func(ptr, 0, len);
    }
}
