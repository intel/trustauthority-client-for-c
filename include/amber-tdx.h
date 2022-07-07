/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_DCAP_TDX__
#define __AMBER_DCAP_TDX__

#include <amber-types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AMBER_STATUS_TDX_ERROR_BASE 0x3000

int tdx_adapter_new(evidence_adapter** adapter);
int tdx_adapter_free(evidence_adapter* adapter);
int tdx_collect_evidence(amber_evidence* evidence, 
                            void* ctx, 
                            amber_nonce* nonce, 
                            uint8_t* user_data,
                            uint32_t user_data_len);

#ifdef __cplusplus
}
#endif

#endif