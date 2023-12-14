/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TRUSTAUTHORITY_DCAP_mock__
#define __TRUSTAUTHORITY_DCAP_mock__

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct mock_adapter_context
    {
        int eid;
        void *report_callback;
    } mock_adapter_context;

    int mock_adapter_new(evidence_adapter **adapter, int eid, void *report_function);
    int mock_collect_evidence(void *ctx,
                              evidence *evidence,
                              nonce *nonce,
                              uint8_t *user_data,
                              uint32_t user_data_len);

#ifdef __cplusplus
}
#endif

#endif
