/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include <string.h>
#include "appraisal_request.h"
#include <base64.h>
#include <types.h>
#include <json.h>
#include <log.h>

/**
 * Marshals the request in JSON form to be sent to Intel Trust Authority:
 * {
 *	"quote": "<SGX/TDX quote base 64 encoded>",
 *	"verifier_nonce":
 *	{
 *		"val":"",
 *		"iat":"",
 *		"signature":"",
 *	},
 *	"runtime_data": ""
 * }
 */
TRUST_AUTHORITY_STATUS json_marshal_appraisal_request(appraisal_request *request,
		char **json)
{
	int result = STATUS_OK;
	char *b64 = NULL;
	size_t input_length = 0, output_length = 0;
	json_t *jansson_request = NULL;
	json_t *jansson_nonce = NULL;
	json_t *policies = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_OK;

	if (NULL == request)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	jansson_request = json_object();
	// quote
	input_length = request->quote_len;
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)calloc(1, output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	result = base64_encode(request->quote, input_length, b64, output_length, false);
	if (BASE64_SUCCESS != result)
	{
		status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(jansson_request, "quote", json_string(b64));
	free(b64);
	b64 = NULL;

	// signed_nonce
	result = get_jansson_nonce(request->verifier_nonce, &jansson_nonce);
	if (STATUS_OK != result)
	{
		return result;
	}

	json_object_set(jansson_request, "verifier_nonce", jansson_nonce);

	// userdata
	if (request->runtime_data_len > 0)
	{
		input_length = request->runtime_data_len;
		output_length = ((input_length + 2) / 3) * 4 + 1;
		b64 = (char *)calloc(1, output_length * sizeof(char));
		if (b64 == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		result = base64_encode(request->runtime_data, input_length, b64, output_length, false);
		if (BASE64_SUCCESS != result)
		{
			status = STATUS_JSON_ENCODING_ERROR;
			goto ERROR;
		}

		json_object_set(jansson_request, "runtime_data", json_string(b64));
		free(b64);
		b64 = NULL;
	}

	// userdata
	if (request->user_data_len > 0)
	{
		input_length = request->user_data_len;
		output_length = ((input_length + 2) / 3) * 4 + 1;
		b64 = (char *)calloc(1, output_length * sizeof(char));
		if (b64 == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		result = base64_encode(request->user_data, input_length, b64, output_length, false);
		if (BASE64_SUCCESS != result)
		{
			status = STATUS_JSON_ENCODING_ERROR;
			goto ERROR;
		}

		json_object_set(jansson_request, "user_data", json_string(b64));
		free(b64);
		b64 = NULL;
	}
	if (request->token_signing_alg != NULL)
	{
		json_object_set(jansson_request, "token_signing_alg", json_string(request->token_signing_alg));
	}
	json_object_set(jansson_request, "policy_must_match", json_boolean(request->policy_must_match));

	// policy_ids
	policies = json_array();
	json_object_set_new(jansson_request, "policy_ids", policies);
	for (int i = 0; i < request->policy_ids->count; i++)
	{
		json_array_append(policies, json_string(request->policy_ids->ids[i]));
	}
	// eventlog
	if (request->event_log_len > 0)
	{
		input_length = request->event_log_len;
		output_length = ((input_length + 2) / 3) * 4 + 1;
		b64 = (char *)calloc(1, output_length * sizeof(char));
		if (b64 == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		result = base64_encode(request->event_log, input_length, b64, output_length, false);
		if (BASE64_SUCCESS != result)
		{
			status = STATUS_JSON_ENCODING_ERROR;
			goto ERROR;
		}

		json_object_set(jansson_request, "event_log", json_string(b64));
	}
	*json = json_dumps(jansson_request, JANSSON_ENCODING_FLAGS);
	if (NULL == *json)
	{
		return STATUS_JSON_ENCODING_ERROR;
	}

	DEBUG("Appraisal Request: %s", *json);

ERROR:
	if(b64 != NULL)
	{
		free(b64);
		b64 = NULL;
	}

	return status;
}
