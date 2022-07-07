/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_TYPES_H__
#define __AMBER_TYPES_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_LEN          64
#define API_KEY_MAX_LEN     64
#define CLUSTER_URL_MAX_LEN 128
#define MAX_USER_DATA_LEN   1024    // 1k
#define MAX_EVIDENCE_LEN    8*1024  // 8k

typedef struct amber_version {
    char name[64];
    char semver[16];
    char commit[16];
    char build_date[64];
} amber_version;

typedef struct amber_token {
    char* jwt;
} amber_token;

typedef struct amber_evidence {
    uint32_t type;
    uint8_t* data;
    uint32_t data_len;
    uint8_t* user_data;
    uint32_t user_data_len;
} amber_evidence;

typedef struct amber_nonce {
    uint8_t* nonce;
    uint32_t nonce_len;
    uint8_t* signature;
    uint32_t signature_len;
} amber_nonce;

typedef struct amber_policies {
    char** ids;          
    uint32_t count;
} amber_policies;

// The evidence_adapter defines an abstraction for collecting evidence
// for difference implementations (ex. SGX, TDX, TPM, SPDM, etc.).
#define EVIDENCE_TYPE_SGX 0x53475800 // 'SGX0'
#define EVIDENCE_TYPE_TDX 0x54445800 // 'TDX0'

typedef int (*evidence_callback)(amber_evidence* evidence, 
                                    void* ctx, 
                                    amber_nonce* nonce, 
                                    uint8_t* user_data,
                                    uint32_t user_data_len);

typedef struct evidence_adapter {
    void* ctx;
    evidence_callback collect_evidence;
} evidence_adapter;

typedef enum {
    AMBER_STATUS_OK                     = 0x0,
    AMBER_STATUS_UNKNOWN_ERROR          = 0x001,

    AMBER_STATUS_INPUT_ERROR            = 0x100,
    AMBER_STATUS_NULL_API,
    AMBER_STATUS_NULL_API_KEY,
    AMBER_STATUS_INVALID_API_KEY,
    AMBER_STATUS_NULL_CLUSTER_URL,
    AMBER_STATUS_INVALID_CLUSTER_URL,
    AMBER_STATUS_NULL_NONCE,
    AMBER_STATUS_NULL_ADAPTER,
    AMBER_STATUS_NULL_EVIDENCE,
    AMBER_STATUS_NULL_VERSION,
    AMBER_STATUS_NULL_TOKEN,
    AMBER_STATUS_INVALID_USER_DATA,
    AMBER_STATUS_INVALID_USER_DATA_LEN,

    AMBER_STATUS_INTERNAL_ERROR         = 0x600,
    AMBER_STATUS_ALLOCATION_ERROR,
    AMBER_STATUS_INVALID_PARAMETER,
    AMBER_STATUS_NULL_ADAPTER_CTX,
    AMBER_STATUS_QUOTE_ERROR,

    AMBER_STATUS_REST_ERROR            = 0x700,
    AMBER_STATUS_GET_VERSION_ERROR,
    AMBER_STATUS_GET_NONCE_ERROR,
    AMBER_STATUS_POST_TOKEN_ERROR,

    AMBER_STATUS_JSON_ERROR             = 0x800,
    AMBER_STATUS_JSON_ENCODING_ERROR,
    AMBER_STATUS_JSON_DECODING_ERROR,
    AMBER_STATUS_JSON_VERSION_PARSING_ERROR,
    AMBER_STATUS_JSON_NONCE_PARSING_ERROR,
    AMBER_STATUS_JSON_TOKEN_PARSING_ERROR,

    AMBER_STATUS_MAX
} AMBER_STATUS;

#ifdef __cplusplus
}
#endif

#endif