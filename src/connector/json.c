/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include <string.h>
#include <types.h>
#include "json.h"
#include "base64.h"
#include "appraisal_request.h"
#include <log.h>

#define COUNT_OF(x) ((sizeof(x) / sizeof(0 [x])) / ((size_t)(!(sizeof(x) % sizeof(0 [x])))))

/**
 * Unmarshals the request in nonce struct form from JSON string:
 * {
 *	"val": "",
 *	"iat":"".
 *	"signature":""
 * }
 */
TRUST_AUTHORITY_STATUS json_unmarshal_nonce(nonce *nonce,
		const char *json)
{
	json_t *nonce_json = NULL;
	json_t *tmp = NULL;
	json_error_t error;
	size_t base64_input_length = 0, output_length = 0;
	unsigned char *buf = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_OK;

	if (NULL == nonce)
	{
		return STATUS_NULL_NONCE;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	struct buffer_map
	{
		uint8_t **ptr;
		uint32_t *len_ptr;
		char *json_name;
	} mappings[] = {
		{&nonce->val, &nonce->val_len, "val"},
		{&nonce->iat, &nonce->iat_len, "iat"},
		{&nonce->signature, &nonce->signature_len, "signature"},
	};

	nonce_json = json_loads(json, 0, &error);
	if (!nonce_json)
	{
		return STATUS_JSON_NONCE_PARSING_ERROR;
	}

	if (json_is_object(nonce_json))
	{
		for (int i = 0; i < COUNT_OF(mappings); i++)
		{

			tmp = json_object_get(nonce_json, mappings[i].json_name);
			if (NULL == tmp || !json_is_string(tmp))
			{
				return STATUS_JSON_NONCE_PARSING_ERROR;
			}

			base64_input_length = strlen(json_string_value(tmp));
			output_length = (base64_input_length / 4) * 3; // Estimate the output length
			buf = (unsigned char *)calloc(output_length + 1, sizeof(unsigned char));
			if (NULL == buf)
			{
				return STATUS_ALLOCATION_ERROR;
			}
			int status = base64_decode(json_string_value(tmp), base64_input_length, buf, &output_length);
			if (BASE64_SUCCESS != status)
			{
				status = STATUS_JSON_DECODING_ERROR;
				goto ERROR;
			}

			if (output_length <= 0 || output_length > MAX_USER_DATA_LEN)
			{
				ERROR("Error: Failed to decode Nonce field '%s'\n", mappings[i].json_name);
				status = STATUS_JSON_NONCE_PARSING_ERROR;
				goto ERROR;
			}

			*mappings[i].ptr = (uint8_t *)calloc(output_length + 1, sizeof(uint8_t));
			if (NULL == *mappings[i].ptr)
			{
				status = STATUS_ALLOCATION_ERROR;
				goto ERROR;
			}

			memcpy(*mappings[i].ptr, buf, output_length);
			*mappings[i].len_ptr = output_length;

			free(buf);
			buf = NULL;
			output_length = 0;
			base64_input_length = 0;
		}
		if (nonce_json)
		{
			json_decref(nonce_json);
			nonce_json = NULL;
		}
	}
	else
	{
		ERROR("Error: Invalid json type\n");
		return STATUS_JSON_NONCE_PARSING_ERROR;
	}

ERROR:
	if(buf != NULL)
	{
		free(buf);
		buf = NULL;
	}

	return status;
}

//This encodes the nonce and convert to json format like val: <base 64 encoded nonce>
TRUST_AUTHORITY_STATUS get_jansson_nonce(nonce *nonce,
		json_t **jansson_nonce)
{
	char *b64 = NULL;
	size_t input_length = 0, output_length = 0;
	TRUST_AUTHORITY_STATUS ret_status = STATUS_OK;

	if (NULL == nonce)
	{
		return STATUS_NULL_NONCE;
	}

	if (NULL == jansson_nonce)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*jansson_nonce = json_object();
	input_length = nonce->val_len;
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)calloc(1, output_length * sizeof(char));
	if (NULL == b64)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	int status = base64_encode(nonce->val, input_length, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		ret_status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(*jansson_nonce, "val", json_string(b64));
	free(b64);
	b64 = NULL;

	input_length = nonce->iat_len;
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)calloc(1, output_length * sizeof(char));
	if (NULL == b64)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	status = base64_encode(nonce->iat, input_length, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		ret_status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(*jansson_nonce, "iat", json_string(b64));
	free(b64);
	b64 = NULL;

	input_length = nonce->signature_len;
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)calloc(1, output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	status = base64_encode(nonce->signature, input_length, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		ret_status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(*jansson_nonce, "signature", json_string(b64));

ERROR:
	if (b64 != NULL)
	{
		free(b64);
		b64 = NULL;
	}

	return ret_status;
}

//This converts nonce data struct to json format like val:"value"
TRUST_AUTHORITY_STATUS json_marshal_nonce(nonce *nonce,
		char **json)
{
	int result;
	json_t *jansson_nonce = NULL;

	if (NULL == nonce)
	{
		return STATUS_NULL_NONCE;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	result = get_jansson_nonce(nonce, &jansson_nonce);
	if (STATUS_OK != result)
	{
		return result;
	}

	*json = json_dumps(jansson_nonce, JANSSON_ENCODING_FLAGS);
	if (NULL == *json)
	{
		return STATUS_JSON_ENCODING_ERROR;
	}
	if (jansson_nonce)
	{
		json_decref(jansson_nonce);
		jansson_nonce = NULL;
	}
	return STATUS_OK;
}

//This encodes the quote and convert to json format like evidence: <base 64 encoded nonce>
TRUST_AUTHORITY_STATUS get_jansson_evidence(evidence *evidence,
		json_t **jansson_evidence)
{
	char *b64 = NULL;
	size_t input_length = 0, output_length = 0;
	TRUST_AUTHORITY_STATUS ret_status = STATUS_OK;

	if (NULL == evidence)
	{
		return STATUS_NULL_EVIDENCE;
	}

	if (NULL == jansson_evidence)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*jansson_evidence = json_object();
	json_object_set(*jansson_evidence, "type", json_integer(evidence->type));

	input_length = strlen(evidence->evidence);
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	int status = base64_encode(evidence->evidence, input_length, b64, output_length, true);
	if (BASE64_SUCCESS != status)
	{
		ret_status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(*jansson_evidence, "evidence", json_string(b64));
	free(b64);
	b64 = NULL;

	input_length = strlen(evidence->user_data);
	output_length = ((input_length + 2) / 3) * 4 + 1;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	status = base64_encode(evidence->user_data, input_length, b64, output_length, true);
	if (BASE64_SUCCESS != status)
	{
		ret_status = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(*jansson_evidence, "user_data", json_string(b64));

ERROR:
	if( b64 != NULL)
	{
		free(b64);
		b64 = NULL;
	}

	return ret_status;
}

//This converts evidence struct to json string
TRUST_AUTHORITY_STATUS json_marshal_evidence(evidence *evidence,
		char **json)
{
	int result;
	json_t *jansson_evidence = NULL;

	if (NULL == evidence)
	{
		return STATUS_NULL_EVIDENCE;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	result = get_jansson_evidence(evidence, &jansson_evidence);
	if (result != STATUS_OK)
	{
		return result;
	}

	*json = json_dumps(jansson_evidence, JANSSON_ENCODING_FLAGS);
	if (NULL == *json)
	{
		return STATUS_JSON_ENCODING_ERROR;
	}

	if (jansson_evidence)
	{
		json_decref(jansson_evidence);
		jansson_evidence = NULL;
	}

	return STATUS_OK;
}

//This converts json string to token struct format
TRUST_AUTHORITY_STATUS json_unmarshal_token(token *token,
		const char *json)
{
	json_t *jansson_token = NULL;
	json_t *tmp = NULL;
	json_error_t error;

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	jansson_token = json_loads(json, 0, &error);
	if (!jansson_token)
	{
		return STATUS_JSON_TOKEN_PARSING_ERROR;
	}

	tmp = json_object_get(jansson_token, "token");
	if (NULL == tmp || !json_is_string(tmp))
	{
		return STATUS_JSON_TOKEN_PARSING_ERROR;
	}

	size_t size = strlen(json_string_value(tmp));
	token->jwt = (char *)calloc(size + 1, sizeof(char));
	if (NULL == token->jwt)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	memcpy(token->jwt, json_string_value(tmp), size);

	return STATUS_OK;
}

//This converts token struct format to json string token: ""
TRUST_AUTHORITY_STATUS json_marshal_token(token *token,
		char **json)
{
	json_t *jansson_token = NULL;

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	jansson_token = json_object();

	json_object_set(jansson_token, "token", json_string(token->jwt));

	*json = json_dumps(jansson_token, JANSSON_ENCODING_FLAGS);
	if (NULL == *json)
	{
		return STATUS_JSON_ENCODING_ERROR;
	}

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS json_unmarshal_token_signing_cert(jwk_set **key_sets,
		const char *json)
{
	json_t *jansson_sign_cert;
	json_t *tmp;
	json_error_t error;

	if (NULL == key_sets)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == json)
	{
		return STATUS_INVALID_PARAMETER;
	}

	jansson_sign_cert = json_loads(json, 0, &error);
	if (!jansson_sign_cert)
	{
		return STATUS_JSON_SIGN_CERT_PARSING_ERROR;
	}

	json_t *keys_arr = json_object_get(jansson_sign_cert, "keys");
	if (!keys_arr)
	{
		return STATUS_JSON_SIGN_CERT_PARSING_KEYS_FIELD_NOT_FOUND_ERROR;
	}

	if (!json_is_array(keys_arr))
	{
		return STATUS_JSON_SIGN_CERT_PARSING_KEYS_FIELD_NOT_AN_ARRAY_ERROR;
	}

	size_t keys_count = json_array_size(keys_arr);
	*key_sets = (jwk_set *)malloc(sizeof(jwk_set));
	if (NULL == *key_sets)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	(*key_sets)->key_cnt = keys_count;
	(*key_sets)->keys = (jwks **)calloc(keys_count, sizeof(jwks *));
	if (NULL == (*key_sets)->keys)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	jwks *key = NULL;

	for (size_t i = 0; i < keys_count; i++)
	{
		(*key_sets)->keys[i] = (jwks *)calloc(1, sizeof(jwks));
		key = (*key_sets)->keys[i];
		
		json_t *key_obj = json_array_get(keys_arr, i);
		json_t *kty_obj = json_object_get(key_obj, "kty");
		json_t *kid_obj = json_object_get(key_obj, "kid");
		json_t *n_obj = json_object_get(key_obj, "n");
		if (NULL == n_obj)
		{
			json_decref(jansson_sign_cert);
			return STATUS_JSON_SIGN_CERT_PARSING_MODULUS_MISSING_ERROR;
		}
		json_t *e_obj = json_object_get(key_obj, "e");
		if (NULL == e_obj)
		{
			json_decref(jansson_sign_cert);
			return STATUS_JSON_SIGN_CERT_PARSING_EXPONENT_MISSING_ERROR;
		}
		json_t *alg_obj = json_object_get(key_obj, "alg");
		json_t *x5c_arr_obj = json_object_get(key_obj, "x5c");

		if (!x5c_arr_obj || !json_is_array(x5c_arr_obj))
		{
			json_decref(jansson_sign_cert);
			return STATUS_JSON_SIGN_CERT_PARSING_KEYS_X5C_FIELD_NOT_AN_ARRAY_ERROR;
		}

		size_t x5c_count = json_array_size(x5c_arr_obj);
		key->num_of_x5c = x5c_count;
		key->x5c = (char **)calloc(x5c_count, sizeof(char *));
		if (NULL == key->x5c)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		for (size_t j = 0; j < x5c_count; j++)
		{
			json_t *x5c_obj = json_array_get(x5c_arr_obj, j);
			if (!x5c_obj || !json_is_string(x5c_obj))
			{
				json_decref(jansson_sign_cert);
				return STATUS_JSON_SIGN_CERT_PARSING_KEYS_X5C_OBJECT_ERROR;
			}
			const char *x5c = json_string_value(x5c_obj);
			size_t x5c_length = strlen(x5c);

			key->x5c[j] = (char *)malloc((x5c_length + 1) * sizeof(char));
			if (key->x5c[j] == NULL)
			{
				return STATUS_ALLOCATION_ERROR;
			}
			strncpy((char *)key->x5c[j], x5c, x5c_length);
			key->x5c[j][x5c_length] = '\0';
		}

		// Copy values to the cert structure
		const char *kty = json_string_value(kty_obj);
		const char *kid = json_string_value(kid_obj);
		const char *n = json_string_value(n_obj);
		const char *e = json_string_value(e_obj);
		const char *alg = json_string_value(alg_obj);
		size_t kty_length = strlen(kty);
		size_t kid_length = strlen(kid);
		size_t n_length = strlen(n);
		size_t e_length = strlen(e);
		size_t alg_length = strlen(alg);

		key->keytype = (char *)malloc((kty_length + 1) * sizeof(char));
		if (key->keytype == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}

		strncpy((char *)key->keytype, kty, kty_length);
		key->keytype[kty_length] = '\0';

		key->kid = (char *)malloc((kid_length + 1) * sizeof(char));
		if (key->kid == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}

		strncpy((char *)key->kid, kid, kid_length);
		key->kid[kid_length] = '\0';

		key->n = (char *)malloc((n_length + 1) * sizeof(char));
		if (key->n == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}

		strncpy((char *)key->n, n, n_length);
		key->n[n_length] = '\0';

		key->e = (char *)malloc((e_length + 1) * sizeof(char));
		if (key->e == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}

		strncpy((char *)key->e, e, e_length);
		key->e[e_length] = '\0';

		key->alg = (char *)malloc((alg_length + 1) * sizeof(char));
		if (key->alg == NULL)
		{
			return STATUS_ALLOCATION_ERROR;
		}

		strncpy((char *)key->alg, alg, alg_length);
		key->alg[alg_length] = '\0';
	}

	if (jansson_sign_cert)
	{
		json_decref(jansson_sign_cert);
		jansson_sign_cert = NULL;
	}

	return STATUS_OK;
}

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
