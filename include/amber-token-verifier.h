/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_TOKEN_VERIFIER_H__
#define __AMBER_TOKEN_VERIFIER_H__

#include <amber-types.h>

#ifdef __cplusplus
extern "C" {
#endif
// Verify an Amber token against the token signing certificate.
AMBER_STATUS amber_verify_token(amber_token* token, char* token_certificate_pem);

#ifdef __cplusplus
}
#endif

#endif