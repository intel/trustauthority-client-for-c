/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <amber-sgx.h>
#include <amber-types.h>

typedef struct sgx_adapter_context {
    int eid;
} sgx_adapter_context;

int sgx_adapter_new(evidence_adapter** adapter, int eid)
{
    sgx_adapter_context* ctx = NULL;

    if (adapter == NULL) 
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_NULL_ADAPTER;
    }

    *adapter = (evidence_adapter*)malloc(sizeof(evidence_adapter));
    if (*adapter == NULL)
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_ALLOCATION_ERROR;
    }

    ctx = calloc(1, sizeof(sgx_adapter_context));
    if (ctx == NULL)
    {
        free(*adapter);
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_ALLOCATION_ERROR;
    }

    ctx->eid = eid;

    (*adapter)->ctx = ctx;

    return AMBER_STATUS_OK;
}

int sgx_adapter_free(evidence_adapter* adapter)
{
    if (adapter != NULL)
    {
        if (adapter->ctx != NULL) 
        {
            free(adapter->ctx);
        }

        free(adapter);
    }
}

int sgx_collect_evidence(amber_evidence* evidence, 
                            void* ctx, 
                            amber_nonce* nonce, 
                            uint8_t* user_data,
                            uint32_t user_data_len)
{
    sgx_adapter_context* sgx_ctx = NULL;

    if (ctx == NULL)
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_NULL_ADAPTER_CTX;
    }

    if (evidence == NULL) 
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_NULL_EVIDENCE;
    }

    if(nonce == NULL)
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_NULL_NONCE;
    }

    if(user_data_len > 0 && user_data == NULL)
    {
        return AMBERS_STATUS_SGX_ERROR_BASE + AMBER_STATUS_INVALID_USER_DATA;
    }

    sgx_ctx = (sgx_adapter_context*)ctx;

    // TASK:  Implement sgx_adapter  
    // Get report/quote here, apply user data, etc.
    // Assumes that 'eid' is pointing refers to an enclave that
    // has been loaded and that has report function that meets
    // Amber requirements.

    evidence->type = EVIDENCE_TYPE_SGX;


    return AMBER_STATUS_OK;
}