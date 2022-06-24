/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <amber-api.h>
#include <amber-types.h>
#include "json.h"
#include "appraisal_request.h"
#include "rest.h"
#include <log.h>
#include "base64.h"

typedef struct amber_api {
    char api_key[API_KEY_MAX_LEN+1];
    char cluster_url[CLUSTER_URL_MAX_LEN+1];
} amber_api;

AMBER_STATUS amber_new(amber_api** api, 
                        const char* api_key, 
                        const char* cluster_url) 
{
    if (api == NULL)
    {
        return AMBER_STATUS_NULL_API;
    }

    if(api_key == NULL)
    {
        return AMBER_STATUS_NULL_API_KEY;
    }

    if(cluster_url == NULL)
    {
        return AMBER_STATUS_NULL_CLUSTER_URL;
    }

    if(strnlen(api_key, API_KEY_MAX_LEN+1) > API_KEY_MAX_LEN)
    {
        return AMBER_STATUS_INVALID_API_KEY;
    }

    if(strnlen(cluster_url, CLUSTER_URL_MAX_LEN+1) > CLUSTER_URL_MAX_LEN)
    {
        return AMBER_STATUS_INVALID_CLUSTER_URL;
    }

    // TODO:  Validate format of api_key and cluster_url

    *api = (amber_api*)calloc(1, sizeof(amber_api));
    if(*api == NULL)
    {
        return AMBER_STATUS_ALLOCATION_ERROR;
    }

    strncpy((*api)->api_key, api_key, API_KEY_MAX_LEN);
    strncpy((*api)->cluster_url, cluster_url, CLUSTER_URL_MAX_LEN);
    
    return AMBER_STATUS_OK;
}

AMBER_STATUS amber_get_version(amber_api* api, amber_version* version)
{
    int result = AMBER_STATUS_OK;
    char* json = NULL;
    char url[CLUSTER_URL_MAX_LEN+1] = {0};

    strncat(url, api->cluster_url, CLUSTER_URL_MAX_LEN);
    strncat(url, "/appraisal/v1/version", CLUSTER_URL_MAX_LEN);
    DEBUG("version url:  %s", url);

    json = get_request(url, api->api_key, NULL, NULL);
    if(json == NULL)
    {
        return AMBER_STATUS_GET_VERSION_ERROR;
    }

    result = json_unmarshal_version(version, json);
    if (result != AMBER_STATUS_OK)
    {
        // TODO: log message
        return result;
    }
   
    free(json);
    return result;
}

AMBER_STATUS amber_get_nonce(amber_api* api, amber_nonce* nonce)
{
    int result = AMBER_STATUS_OK;
    char* json = NULL;
    char url[CLUSTER_URL_MAX_LEN+1] = {0};

    if(api == NULL)
    {
        return AMBER_STATUS_NULL_API;
    }

    if(nonce == NULL)
    {
        return AMBER_STATUS_NULL_NONCE;
    }

    strncat(url, api->cluster_url, CLUSTER_URL_MAX_LEN);
    strncat(url, "/appraisal/v1/nonce", CLUSTER_URL_MAX_LEN);
    DEBUG("nonce url: %s", url)

    json = get_request(url, api->api_key, NULL, NULL);
    if(json == NULL)
    {
        return AMBER_STATUS_GET_NONCE_ERROR; 
    }

    result = json_unmarshal_nonce(nonce, json);
    if (result != AMBER_STATUS_OK)
    {
        // TODO: log message
        return result;
    }

    free(json);
    return result;
}

AMBER_STATUS amber_get_token(amber_api* api, 
                                amber_token* token, 
                                amber_policies* policies,
                                amber_evidence* evidence, 
                                amber_nonce* nonce)
{
    int               result = AMBER_STATUS_OK;
    appraisal_request request = {0};
    char*             json = NULL;
    char              url[CLUSTER_URL_MAX_LEN+1] = {0};
    char*             response = NULL;

    if(api == NULL)
    {
        return AMBER_STATUS_NULL_API;
    }

    if(token == NULL)
    {
        return AMBER_STATUS_INVALID_PARAMETER;
    }

    if(evidence == NULL)
    {
        return AMBER_STATUS_INVALID_PARAMETER;
    }
    
    if(evidence->data == NULL)
    {
        ERROR("The evidence data was not provided");
        return AMBER_STATUS_INVALID_PARAMETER;
    }

    if(evidence->data_len > MAX_EVIDENCE_LEN)
    {
        ERROR("Evidence data size %d exceeds maximum length %d", evidence->data_len, MAX_EVIDENCE_LEN);
        return AMBER_STATUS_INVALID_PARAMETER;
    }
        
    if(nonce == NULL)
    {
        ERROR("The nonce was not provided");
        return AMBER_STATUS_INVALID_PARAMETER;
    }

    strncat(url, api->cluster_url, CLUSTER_URL_MAX_LEN);
    strncat(url, "/appraisal/v1/appraise", CLUSTER_URL_MAX_LEN);
    DEBUG("token url: %s", url);

    request.quote_len = evidence->data_len;
    request.quote = evidence->data; 
    request.nonce = nonce;
    request.policies = policies;

    result = json_marshal_appraisal_request(&request, &json);
    if (result != AMBER_STATUS_OK)
    {
        goto error;
    }

    // TODO:  consider changing rest fx to return status (http status)
    response = post_request(url, api->api_key, ACCEPT_APPLICATION_JWT, CONTENT_TYPE_APPLICATION_JSON, json);
    if (response == NULL)
    {
        ERROR("Failed to get token from %s", url);
        result = AMBER_STATUS_POST_TOKEN_ERROR;
        goto error;
    }

    token->jwt = response;

error:

    // TODO:  token memory management
    // if(response)
    // {
    //     free(response);
    // }

    if (json)
    {
        free(json);
    }

    return result;
}

AMBER_STATUS amber_get_token_signing_certificate(amber_api* api, 
                                                    char** pem_certificate)
{
    // TASK:  Get token signing certificate from Amber
    return AMBER_STATUS_UNKNOWN_ERROR;    
}

AMBER_STATUS amber_free_api(amber_api* api)
{
    if (api == NULL)
    {
        return AMBER_STATUS_NULL_API;
    }

    free(api);
    return AMBER_STATUS_OK;
}

AMBER_STATUS amber_free_nonce(amber_nonce* nonce)
{
    if (nonce == NULL)
    {
        return AMBER_STATUS_NULL_NONCE;
    }

    if(nonce->nonce != NULL)
    {
        free(nonce->nonce);
    }

    if(nonce->signature != NULL)
    {
        free(nonce->signature);
    }

    free(nonce);
    return AMBER_STATUS_OK;
}

AMBER_STATUS amber_free_version(amber_version* version)
{
    if(version == NULL)
    {
        return AMBER_STATUS_NULL_VERSION;
    }

    free(version);
    return AMBER_STATUS_OK;
}

AMBER_STATUS amber_free_token(amber_token* token)
{
    if(token == NULL)
    {
        return AMBER_STATUS_NULL_TOKEN;
    }

    if(token->jwt != NULL)
    {
        free(token->jwt);
    }

    free(token);
    return AMBER_STATUS_OK;
}

AMBER_STATUS amber_free_evidence(amber_evidence* evidence)
{
    if(evidence == NULL)
    {
        return AMBER_STATUS_NULL_EVIDENCE;
    }

    if(evidence->data != NULL)
    {
        free(evidence->data);
    }

    if(evidence->user_data != NULL)
    {
        free(evidence->user_data);
    }

    free(evidence);
    return AMBER_STATUS_OK;
}
