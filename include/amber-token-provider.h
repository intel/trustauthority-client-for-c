/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_TOKEN_PROVIDER_H__
#define __AMBER_TOKEN_PROVIDER_H__

#include <amber-api.h>

#ifdef __cplusplus
extern "C" {
#endif

// Utility function that gets an amber_nonce, evidence (provided by 
// evidence_adapter) and gets an amber_token from Amber SaaS.
AMBER_STATUS amber_collect_token(amber_api* api, 
                                    amber_token* token, 
                                    amber_policies* policies,
                                    evidence_adapter* adapter,
                                    uint8_t* user_data, 
                                    uint32_t user_data_len);

// Utility function that gets an amber_nonce, evidence (provided by 
// evidence_callback) and gets an amber_token from Amber SaaS.
AMBER_STATUS amber_collect_token_callback(amber_api* api, 
                                            amber_token* token, 
                                            amber_policies* policies,
                                            evidence_callback callback, 
                                            void* ctx, 
                                            uint8_t* user_data, 
                                            uint32_t user_data_len);
                                            
#ifdef __cplusplus
}
#endif

#endif