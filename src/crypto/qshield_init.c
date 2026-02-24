/*
 * Copyright 2026 QShield Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * QShield library initialisation and cleanup.
 */

#include "qshield/qshield.h"
#include <oqs/oqs.h>

int qshield_init(void)
{
    OQS_init();
    return 0;
}

void qshield_cleanup(void)
{
    OQS_destroy();
}
