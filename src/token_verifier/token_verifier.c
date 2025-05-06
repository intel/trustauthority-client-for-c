/*
 * Copyright (C) 2023-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <token_verifier.h>
#include <base64.h>
#include <json.h>
#include <log.h>
#include <openssl/x509.h>
#include <jwt.h>
#include "util.h"

// Parse and validate the elements of token, get token signing certificate from Intel Trust Authority
// and Initiate verifying the token against the token signing certificate.
TRUST_AUTHORITY_STATUS verify_token(token *token,
		char *base_url,
		char *jwks_data,
		jwt_t **parsed_token,
		const int retry_max,
		const int retry_wait_time)
{
	int result;
	const char *formatted_pub_key = NULL, *token_kid = NULL;
	jwk_set *key_set = NULL;
	jwks *jwks = NULL;
	EVP_PKEY *pubkey = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_OK;

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == parsed_token)
	{
		return STATUS_NULL_TOKEN;
	}
	result = parse_token_header_for_kid(token, &token_kid);
	if (result != STATUS_OK || token_kid == NULL)
	{
		ERROR("Error: Failed to parse token for Key ID: %d\n", result);
		return result;
	}

	if (NULL == jwks_data)
	{
		if (NULL == base_url)
		{
			return STATUS_NULL_BASE_URL;
		}
	
		int base_url_len = strnlen(base_url, API_URL_MAX_LEN + 1);
		if (base_url_len > API_URL_MAX_LEN)
		{
			ERROR("Invalid Trust Authority Base URL, must be lesser than %d in length\n", API_URL_MAX_LEN);
			return STATUS_INVALID_BASE_URL;
		}
	
		// Handling trailing slashes in base_url
		if (base_url[base_url_len - 1] == '/')
		{
			base_url[base_url_len - 1] = '\0';
		}

		result = get_token_signing_certificate(base_url, &jwks_data, retry_max, retry_wait_time);
		if (result != STATUS_OK || jwks_data == NULL)
		{
			ERROR("Error: Get jwks failed : %d\n", result);
			status = STATUS_GET_SIGNING_CERT_ERROR;
			goto ERROR;
		}

		DEBUG("Successfully retrieved JWKS response from Intel Trust Authority\n :%s", jwks_data);
	}

	result = json_unmarshal_token_signing_cert(&key_set, jwks_data);
	if (result != STATUS_OK || key_set == NULL)
	{
		ERROR("Error: JWKS unmarshal failed : %d\n", result);
		status = STATUS_JSON_SIGN_CERT_UNMARSHALING_ERROR;
		goto ERROR;
	}
	for (int k=0; k<key_set->key_cnt; k++)
	{
		// Lookup for Key ID matches
		if (strcmp(key_set->keys[k]->kid, token_kid) == 0)
		{
			jwks = key_set->keys[k];
			break;
		}
	}
	if (jwks == NULL)
	{
		status = STATUS_KID_NOT_MATCHING_ERROR;
		goto ERROR;
	}
	// Check the number of signing certificates from JWKS
	if (jwks->num_of_x5c > MAX_ATS_CERT_CHAIN_LEN)
	{
		status = STATUS_JSON_NO_OF_SIGN_CERT_EXCEEDING_ERROR;
		goto ERROR;
	}
	// Do the certificate chain verification of JWKS's x5c
	result = verify_jwks_cert_chain(jwks);
	if (result != STATUS_OK)
	{
		ERROR("Error: Certificate chain verification failed : %d\n", result);
		status = STATUS_VERIFYING_CERT_CHAIN_ERROR;
		goto ERROR;
	}

	result = extract_pubkey_from_certificate(jwks->x5c[0], &pubkey);
	if (result != STATUS_OK || pubkey == NULL)
	{
		ERROR("Error: Extract pubkey failed : %d\n", result);
		status = STATUS_EXTRACT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Format the received public key
	result = format_pubkey(pubkey, &formatted_pub_key);
	if (result != STATUS_OK || formatted_pub_key == NULL)
	{
		ERROR("Error: Format pubkey failed : %d\n", result);
		status = STATUS_FORMAT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Perform the actual token verification here by using libjwt
	result = jwt_decode(parsed_token, (const char *)token->jwt, (const unsigned char *)formatted_pub_key, strlen(formatted_pub_key));
	if (result != STATUS_OK || *parsed_token == NULL)
	{
		ERROR("Error: Token verification failed : %d\n", result);
		status = STATUS_TOKEN_VERIFICATION_FAILED_ERROR;
		goto ERROR;
	}

ERROR:
	if(NULL != formatted_pub_key)
	{
		free((void *)formatted_pub_key);
		formatted_pub_key = NULL;
	}
	if(NULL != token_kid)
	{
		free((void *)token_kid);
		token_kid = NULL;
	}
	if(NULL != jwks_data)
	{
		free(jwks_data);
		jwks_data = NULL;
	}
	jwks_free(key_set);
	EVP_PKEY_free(pubkey);
	return status;
}
