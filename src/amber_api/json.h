/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __AMBER_JSON_H__
#define __AMBER_JSON_H__
#include <amber-types.h>
#include "appraisal_request.h"

#define JANSSON_ENCODING_FLAGS (JSON_ENSURE_ASCII & JSON_COMPACT)

AMBER_STATUS json_unmarshal_version(amber_version* version, const char* json);
AMBER_STATUS json_marshal_version(amber_version* version, char** json);

AMBER_STATUS json_unmarshal_nonce(amber_nonce* nonce, const char* json);
AMBER_STATUS json_marshal_nonce(amber_nonce* nonce, char** json);

AMBER_STATUS json_unmarshal_evidence(amber_evidence* evidence, const char* json);
AMBER_STATUS json_marshal_evidence(amber_evidence* evidence, char** json);

AMBER_STATUS json_unmarshal_token(amber_token* token, const char* json);
AMBER_STATUS json_marshal_token(amber_token* token, char** json);

//int json_marshal_appraisal_request(appraisal_request* request, const char* json);
AMBER_STATUS json_marshal_appraisal_request(appraisal_request* request, char** json);

#endif