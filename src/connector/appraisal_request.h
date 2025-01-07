/*
 * Copyright (C) 2023-2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __APPRAISAL_REQUEST_H__
#define __APPRAISAL_REQUEST_H__

#include "types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * struct containing request sent to Intel Trust Authority for attestation.
 */
typedef struct appraisal_request
{
	uint8_t *quote;
	uint32_t quote_len;
	nonce *verifier_nonce;
	uint8_t *runtime_data;
	uint32_t runtime_data_len;
	uint8_t *user_data;
	uint32_t user_data_len;
	policies *policy_ids;
	uint8_t *event_log;
	uint32_t event_log_len;
	const char *token_signing_alg;
	bool policy_must_match;
} appraisal_request;

	/**
	 * Performs marshaling of the request sent to Intel Trust Authority.
	 * @param request  request appraisal_request to be unmarshalled from json format to appraisal_request type
	 * @param json data to be unmarshalled
	 * @return int containing status
	 */
	TRUST_AUTHORITY_STATUS json_marshal_appraisal_request(appraisal_request *request,
			char **json);

#ifdef __cplusplus
}
#endif

#endif // __APPRAISAL_REQUEST_H__
