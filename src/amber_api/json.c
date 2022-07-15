/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include <string.h>
#include <amber-types.h>
#include "json.h"
#include "base64.h"
#include "appraisal_request.h"
#include <log.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

AMBER_STATUS json_unmarshal_version(amber_version* version, const char *json)
{
    json_t*         jansson_version;
    json_t*         tmp;
    json_error_t    error;

    // TODO:  input parameter checking

    struct field_map {
        char* ptr; 
        size_t size;
        char* json_name;
    } mappings[] = {
        {version->name, sizeof(version->name), "name"},
        {version->semver, sizeof(version->semver), "version"},
        {version->commit, sizeof(version->commit), "gitHash"},
        {version->build_date, sizeof(version->build_date), "buildDate"},
    };
    
    jansson_version = json_loads(json, 0, &error);
    if(!jansson_version)
    {
        printf("Failed to parse version json: %s\n", error.text);
        return AMBER_STATUS_JSON_VERSION_PARSING_ERROR;
    }

    if(json_is_object(jansson_version))
    {
        for(int i = 0; i < COUNT_OF(mappings); i++)
        {
            tmp = json_object_get(jansson_version, mappings[i].json_name);
            if(tmp == NULL || !json_is_string(tmp))
            {
                printf("JSON error: failed to parse '%s'\n", mappings[i].json_name);
                return AMBER_STATUS_JSON_VERSION_PARSING_ERROR;
            }

            strncpy(mappings[i].ptr, json_string_value(tmp), mappings[i].size);
            DEBUG("VERSION: %s->%s MAX[%ld]", mappings[i].json_name, json_string_value(tmp), mappings[i].size);
        }
    } 
    else
    {
        printf("Invalid json type\n");
        return AMBER_STATUS_JSON_VERSION_PARSING_ERROR;
    }

    return AMBER_STATUS_OK;
}

AMBER_STATUS json_marshal_version(amber_version* version, char** json)
{
    // TODO:  Implement conversion from C structure to json (needed?)
    return AMBER_STATUS_UNKNOWN_ERROR;
}

AMBER_STATUS json_unmarshal_nonce(amber_nonce* nonce, const char *json)
{
    json_t*         nonce_json;
    json_t*         tmp;
    json_error_t    error;
    unsigned char*  buf = NULL;
    size_t          len;

    struct buffer_map {
        uint8_t** ptr;
        uint32_t* len_ptr;
        char* json_name;
    } mappings[] = {
        {&nonce->nonce, &nonce->nonce_len, "nonce"},
        {&nonce->signature, &nonce->signature_len, "signature"},
    };

    nonce_json = json_loads(json, 0, &error);
    if(!json)
    {
        printf("Failed to parse nonce json: %s\n", error.text);
        return AMBER_STATUS_JSON_NONCE_PARSING_ERROR;
    }

    if(json_is_object(nonce_json))
    {
        for (int i = 0; i < COUNT_OF(mappings); i++)
        {
            tmp = json_object_get(nonce_json, mappings[i].json_name);
            if(tmp == NULL || !json_is_string(tmp))
            {
                ERROR("JSON error: failed to parse nonce value\n");
                return AMBER_STATUS_JSON_NONCE_PARSING_ERROR;
            }

            Base64Decode(json_string_value(tmp), &buf, &len);
            if(buf == NULL || len <=0 || len > MAX_USER_DATA_LEN)
            {
                printf("Failed to base64 decode nonce field '%s'\n", mappings[i].json_name);
                return AMBER_STATUS_JSON_NONCE_PARSING_ERROR;
            }

            *mappings[i].ptr = (uint8_t*)malloc(len);
            if (*mappings[i].ptr == NULL)
            {
                return AMBER_STATUS_ALLOCATION_ERROR;
            }

            memcpy(*mappings[i].ptr, buf, len);
            *mappings[i].len_ptr = len;

            //DEBUG("NONCE: %s[%ld:%p]->%s", mappings[i].json_name, len, *mappings[i].ptr, json_string_value(tmp));

            free(buf);
            buf = NULL;
        }
    } 
    else
    {
        printf("Invalid json type\n");
        return AMBER_STATUS_JSON_NONCE_PARSING_ERROR;
    }

    return AMBER_STATUS_OK;
}

static AMBER_STATUS get_jansson_nonce(amber_nonce* nonce, json_t** jansson_nonce)
{
    char* b64 = NULL;

    if(nonce == NULL)
    {
        return AMBER_STATUS_NULL_NONCE;
    }

    if (jansson_nonce == NULL)
    {
        ERROR("The nonce json object was not provided");
        return AMBER_STATUS_INVALID_PARAMETER;
    }

    DEBUG("NONCE: @%p", nonce);
    
    *jansson_nonce = json_object();

    Base64Encode(nonce->nonce, nonce->nonce_len, &b64);
    json_object_set(*jansson_nonce, "nonce", json_string(b64));
    free(b64);
    b64 = NULL;

    Base64Encode(nonce->signature, nonce->signature_len, &b64);
    json_object_set(*jansson_nonce, "signature", json_string(b64));
    free(b64);

    return AMBER_STATUS_OK;
}

AMBER_STATUS json_marshal_nonce(amber_nonce* nonce, char** json)
{
    int result;
    json_t* jansson_nonce = NULL;

    if(nonce == NULL)
    {
        return AMBER_STATUS_NULL_NONCE;
    }

    if(json == NULL)
    {
        return AMBER_STATUS_INVALID_PARAMETER;
    }

    result = get_jansson_nonce(nonce, &jansson_nonce);
    if (result != AMBER_STATUS_OK)
    {
        return result;
    }

    *json = json_dumps(jansson_nonce, JANSSON_ENCODING_FLAGS);
    if (*json == NULL)
    {
        ERROR("Failed to dump nonce json\n");
        return AMBER_STATUS_JSON_ENCODING_ERROR;
    }

    free(jansson_nonce);
    return AMBER_STATUS_OK;
}

AMBER_STATUS json_unmarshal_evidence(amber_evidence* evidence, const char* json)
{
    // TODO:  Implement conversion from json to C structure (needed?)
    return AMBER_STATUS_UNKNOWN_ERROR;
}

AMBER_STATUS json_marshal_evidence(amber_evidence* evidence, char** json)
{
    // TODO:  Implement conversion from C structure to json (needed?)
    return AMBER_STATUS_UNKNOWN_ERROR;
}


// TASK:  Consider providing an API that takes the token and returns
// the claims as a json string.
AMBER_STATUS json_unmarshal_token(amber_token* token, const char* json)
{
    return AMBER_STATUS_OK;
}

AMBER_STATUS json_marshal_token(amber_token* token, char** json)
{
    // TODO:  Implement conversion from C structure to json (needed?)
    return AMBER_STATUS_UNKNOWN_ERROR;
}

AMBER_STATUS json_unmarshal_appraisal_request(appraisal_request* request, const char* json)
{
    // TODO:  Implement conversion from json to C structure (needed?)
    return AMBER_STATUS_UNKNOWN_ERROR;
}

AMBER_STATUS json_marshal_appraisal_request(appraisal_request* request, char** json)
{
    int     result = AMBER_STATUS_OK;
    char*   b64 = NULL;
    json_t* jansson_request = NULL;
    json_t* jansson_nonce = NULL;
    json_t* policies = NULL;

    jansson_request = json_object();

    // quote
    Base64Encode(request->quote, request->quote_len, &b64);
    json_object_set(jansson_request, "quote", json_string(b64));
    free(b64);

    // signed_nonce
    result = get_jansson_nonce(request->nonce, &jansson_nonce);
    if (result != AMBER_STATUS_OK)
    {
        ERROR("Failed to create nonce json: %d", result);
        return result;
    }

    json_object_set(jansson_request, "signed_nonce", jansson_nonce);

    // userdata
    Base64Encode(request->user_data, request->user_data_len, &b64);
    json_object_set(jansson_request, "user_data", json_string(b64));
    free(b64);

    // policy_ids
    policies = json_array();
    json_object_set_new(jansson_request, "policy_ids", policies);
    for(int i = 0; i < request->policies->count; i++)
    {
        json_array_append(policies, json_string(request->policies->ids[i]));
    }

    *json = json_dumps(jansson_request, JANSSON_ENCODING_FLAGS);
    if (*json == NULL)
    {
        ERROR("Failed to dump appraisal request json\n");
        return AMBER_STATUS_JSON_ENCODING_ERROR;
    }

    DEBUG("Appraisal Request: %s", *json);
    return AMBER_STATUS_OK;
}
