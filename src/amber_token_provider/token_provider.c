/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <amber-api.h>
#include <amber-token-provider.h>
#include <log.h>

AMBER_STATUS amber_collect_token(amber_api* api, 
                                    amber_token* token, 
                                    amber_policies* policies, 
                                    evidence_adapter* adapter, 
                                    uint8_t* user_data, 
                                    uint32_t user_data_len)
{
    return amber_collect_token_callback(api, 
                                        token, 
                                        policies,
                                        adapter->collect_evidence, 
                                        adapter->ctx, 
                                        user_data, 
                                        user_data_len);
}

AMBER_STATUS amber_collect_token_callback(amber_api* api, 
                                            amber_token* token,
                                            amber_policies* policies, 
                                            evidence_callback callback, 
                                            void* ctx, 
                                            uint8_t* user_data, 
                                            uint32_t user_data_len)
{
    int                 result;
    amber_nonce         nonce = {0};
    amber_evidence      evidence = {0};
    uint8_t             hash[SHA512_LEN] = {0};

    // TODO:  Input validation, pointers, etc.

    result = amber_get_nonce(api, &nonce);
    if (result != AMBER_STATUS_OK) 
    {
        ERROR("Failed to get Amber nonce %d\n", result);
        goto ERROR;
    }

    result = callback(&evidence, ctx, &nonce, user_data, user_data_len);
    if (result != AMBER_STATUS_OK) 
    {
        ERROR("Failed to collect evidence from collector %d\n", result);
        goto ERROR;
    }

    DEBUG("Evidence[%d] @%p", evidence.data_len, evidence.data);

    result = amber_get_token(api, token, policies, &evidence, &nonce);
    if (result != AMBER_STATUS_OK) 
    {
        ERROR("Failed to get Amber token %d\n", result);
        goto ERROR;
    }

ERROR:

    if(nonce.nonce != NULL)
    {
        free(nonce.nonce);
    }

    if(nonce.signature != NULL)
    {
        free(nonce.signature);
    }

    if (evidence.data != NULL) 
    {
        free(evidence.data);
    }

    if (evidence.user_data != NULL) 
    {
        free(evidence.user_data);
    }

    return result;
}