/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_API_H__
#define __AMBER_API_H__

#include <amber-types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct amber_api amber_api;

// Create a new amber_api (rest) client.
AMBER_STATUS amber_new(amber_api** api, 
                        const char* api_key, 
                        const char* cluster_url);

// Get version information from Amber SaaS.
AMBER_STATUS amber_get_version(amber_api* api, amber_version* version);

// Get a new v from Amber SaaS.
AMBER_STATUS amber_get_nonce(amber_api* api, amber_nonce* nonce);

// Get an amber_token providing amber_evidence and amber_nonce.
AMBER_STATUS amber_get_token(amber_api* api, 
                                amber_token* token, 
                                amber_policies* policies,
                                amber_evidence* evidence, 
                                amber_nonce* nonce);

AMBER_STATUS amber_get_token_signing_certificate(amber_api* api, 
                                                    char** pem_certificate);

// Delete/free an amper_api client
AMBER_STATUS amber_free_api(amber_api* api);

// Delete/free an amber_token.
AMBER_STATUS amber_free_token(amber_token* token);

// Delete/free an amber_evidence.
AMBER_STATUS amber_free_evidence(amber_evidence* evidence);

// Delete/free an amber_version.
AMBER_STATUS amber_free_version(amber_version* version);

// Delete/free an amber_nonce.
AMBER_STATUS amber_free_nonce(amber_nonce* nonce);

#ifdef __cplusplus
}
#endif

#endif