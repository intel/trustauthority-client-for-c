/*
 * Copyright (C) 2023-2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __JSON_H__
#define __JSON_H__

#include <types.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define JANSSON_ENCODING_FLAGS (JSON_ENSURE_ASCII & JSON_COMPACT)

	/**
	 * Performs unmarshaling of nonce recieved from Intel Trust Authority
	 * @param nonce nonce pointer containing unmarshalled nonce
	 * @param json const char pointer containing nonce recieved from Intel Trust Authority
	 * @return return status
	 */
	TRUST_AUTHORITY_STATUS json_unmarshal_nonce(nonce *nonce,
			const char *json);

	/**
	 * Performs marshaling of nonce
	 * @param nonce nonce pointer containing marshalled nonce
	 * @param json const char pointer containing nonce recieved from Intel Trust Authority
	 * @return return status
	 */		
	TRUST_AUTHORITY_STATUS json_marshal_nonce(nonce *nonce,
			char **json);

	/**
	 * Performs marshaling of quote
	 * @param evidence evidence pointer containing quote
	 * @param json const char pointer containing evidence from platform
	 * @return int containing status
	 */		
	TRUST_AUTHORITY_STATUS json_marshal_evidence(evidence *evidence,
			char **json);

	/**
	 * Performs unmarshaling of token received from Intel Trust Authority
	 * @param token unmarshalled token in struct token format
	 * @param json token recieved from Intel Trust Authority to be unmarshalled
	 * @return int containing status
	 */		
	TRUST_AUTHORITY_STATUS json_unmarshal_token(token *token,
			const char *json);

	/**
	 * Performs marshaling of token
	 * @param token in struct token format to be marshalled to json format
	 * @param json json format token to be used 
	 * @return int containing status
	 */		
	TRUST_AUTHORITY_STATUS json_marshal_token(token *token,
			char **json);

	/**
	 * Performs umnmarshalling of token signing certificate
	 * @param cert  certificate to be unmarshalled from json format to jwks type
	 * @param json data to be unmarshalled
	 * @return return status
	 */		
	TRUST_AUTHORITY_STATUS json_unmarshal_token_signing_cert(jwk_set **cert,
			const char *json);

	TRUST_AUTHORITY_STATUS get_jansson_nonce(nonce *nonce,
			json_t **jansson_nonce);

	TRUST_AUTHORITY_STATUS get_jansson_evidence(evidence *evidence,
			json_t **jansson_evidence);

#ifdef __cplusplus
}
#endif

#endif // __JSON_H__
