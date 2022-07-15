/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <amber-tdx.h>
#include <amber-types.h>
#include <tdx_attest.h>
#include <openssl/evp.h>

typedef struct tdx_adapter_context {
} tdx_adapter_context;

int tdx_adapter_new(evidence_adapter** adapter)
{
    tdx_adapter_context* ctx = NULL;

    if (adapter == NULL) 
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_NULL_ADAPTER;
    }

    *adapter = (evidence_adapter*)malloc(sizeof(evidence_adapter));
    if (*adapter == NULL)
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_ALLOCATION_ERROR;
    }

    ctx = calloc(1, sizeof(tdx_adapter_context));
    if (ctx == NULL)
    {
        free(*adapter);
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_ALLOCATION_ERROR;
    }

    (*adapter)->ctx = ctx;
    (*adapter)->collect_evidence = tdx_collect_evidence;

    return AMBER_STATUS_OK;
}

int tdx_adapter_free(evidence_adapter* adapter)
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

int tdx_collect_evidence(amber_evidence* evidence, 
                            void* ctx, 
                            amber_nonce* nonce, 
                            uint8_t* user_data,
                            uint32_t user_data_len)
{
    tdx_adapter_context* tdx_ctx = NULL;

    if (ctx == NULL)
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_NULL_ADAPTER_CTX;
    }

    if (evidence == NULL) 
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_NULL_EVIDENCE;
    }

    if(nonce == NULL)
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_NULL_NONCE;
    }

    if(user_data_len > 0 && user_data == NULL)
    {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_INVALID_USER_DATA;
    }

    tdx_ctx = (tdx_adapter_context*)ctx;

    // Hashing Nonce and UserData
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    const EVP_MD *md = EVP_get_digestbyname("sha512");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, nonce->nonce, nonce->nonce_len);
    EVP_DigestUpdate(mdctx, user_data, user_data_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // Fetching Quote from TD
    uint32_t quote_size = 0;
    uint8_t *p_quote_buf = NULL;
    tdx_report_data_t report_data = {{0}};
    tdx_uuid_t selected_att_key_id = {0};
    memcpy(report_data.d, md_value, TDX_REPORT_DATA_SIZE);
    uint32_t ret = tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id,
        &p_quote_buf, &quote_size, 0);
    if (TDX_ATTEST_SUCCESS != ret) {
        printf("tdx_att_get_quote failed: 0x%04x", ret);
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_QUOTE_ERROR;
    }

    // Populating Evidence with TDQuote
    evidence->data = (uint8_t *)calloc(1, quote_size);
    if (NULL == evidence->data) {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_ALLOCATION_ERROR;
    }
    memcpy(evidence->data, p_quote_buf, quote_size);
    evidence->data_len = quote_size;
    tdx_att_free_quote(p_quote_buf);

    // Populating UserData with UserData
    evidence->user_data = (uint8_t *)calloc(1, user_data_len);
    if (NULL == evidence->user_data) {
        return AMBER_STATUS_TDX_ERROR_BASE | AMBER_STATUS_ALLOCATION_ERROR;
    }
    memcpy(evidence->user_data, user_data, user_data_len);
    evidence->user_data_len = user_data_len;

    evidence->type = EVIDENCE_TYPE_TDX;

    return AMBER_STATUS_OK;
}
