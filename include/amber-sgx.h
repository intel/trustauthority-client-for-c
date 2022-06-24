/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_DCAP_SGX__
#define __AMBER_DCAP_SGX__

#include <amber-types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AMBERS_STATUS_SGX_ERROR_BASE 0x2000

int sgx_adapter_new(evidence_adapter** adapter, int eid);
int sgx_adapter_free(evidence_adapter* adapter);
int sgx_collect_evidence(amber_evidence* evidence, 
                            void* ctx, 
                            amber_nonce* nonce, 
                            uint8_t* user_data,
                            uint32_t user_data_len);

#ifdef __cplusplus
}
#endif

#endif