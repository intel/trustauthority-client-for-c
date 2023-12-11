/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <connector.h>
#include <types.h>
#include "json.h"
#include "api.h"
#include "appraisal_request.h"
#include "rest.h"
#include <log.h>
#include "base64.h"
#include <jwt.h>
#include <regex.h>

extern BIGNUM *bignum_base64_decode(const char *base64bignum);

TRUST_AUTHORITY_STATUS trust_authority_connector_new(trust_authority_connector **connector,
		const char *api_key,
		const char *api_url,
		const int retry_max,
		const int retry_wait_time)
{
	size_t base64_input_length = 0, output_length = 0;
	unsigned char *buf = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_INVALID_API_KEY;

	if (NULL == connector)
	{
		return STATUS_NULL_CONNECTOR;
	}

	if (NULL == api_key)
	{
		return STATUS_NULL_API_KEY;
	}

	if (NULL == api_url)
	{
		return STATUS_NULL_API_URL;
	}

	if (strnlen(api_key, API_KEY_MAX_LEN + 1) > API_KEY_MAX_LEN)
	{
		return STATUS_INVALID_API_KEY;
	}

	if (strnlen(api_url, API_URL_MAX_LEN + 1) >
			API_URL_MAX_LEN)
	{
		return STATUS_INVALID_API_URL;
	}
	// Validate format of api_url
	if (0 != is_valid_url(api_url))
	{
		return STATUS_INVALID_API_URL;
	}
	// Validate format of api_key
	status = is_valid_api_key(api_key);
	if (STATUS_OK != status)
	{
		return status;
	}

	*connector = (trust_authority_connector *)calloc(1, sizeof(trust_authority_connector));
	if (NULL == *connector)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	(*connector)->retries = (retry_config *)calloc(1, sizeof(retry_config));
	if (NULL == (*connector)->retries)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	strncpy((*connector)->api_key, api_key, API_KEY_MAX_LEN);
	strncpy((*connector)->api_url, api_url, API_URL_MAX_LEN);
	if (retry_max != 0)
	{
		(*connector)->retries->retry_max = retry_max;
	}
	if (retry_wait_time != 0)
	{
		(*connector)->retries->retry_wait_time = retry_wait_time;
	}

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS get_nonce(trust_authority_connector *connector,
		nonce *nonce,
		const char *request_id,
		response_headers *resp_headers)
{
	int result = STATUS_OK;
	char *json = NULL;
	char *headers = NULL;
	char url[API_URL_MAX_LEN + 1] = {0};
	CURLcode status = CURLE_OK;

	if (NULL == connector)
	{
		return STATUS_NULL_CONNECTOR;
	}

	if (NULL == nonce)
	{
		return STATUS_NULL_NONCE;
	}

	strncat(url, connector->api_url, API_URL_MAX_LEN);
	strncat(url, "/appraisal/v1/nonce", API_URL_MAX_LEN);
	DEBUG("Nonce url: %s\n", url);

	//Get nonce from Intel Trust Authority
	status = get_request(url, connector->api_key, ACCEPT_APPLICATION_JSON, 
			request_id, NULL, &json ,&headers, connector->retries);
	if (NULL == json || CURLE_OK != status)
	{
		ERROR("Error: GET request to %s failed", url);
		return STATUS_GET_NONCE_ERROR;
	}

	//Unmarshal nonce as per struct nonce.
	result = json_unmarshal_nonce(nonce, json);
	if (STATUS_OK != result)
	{
		ERROR("Error: Unmarshalling Nonce - %d\n", result);
		return result;
	}

	//Fetch all the headers recieved.
	size_t size = strlen(headers);
	resp_headers->headers = (char *)calloc(size + 1, sizeof(char));
	if (NULL == resp_headers->headers)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	memcpy(resp_headers->headers, headers, size);

	if (json)
	{
		free(json);
		json = NULL;
	}

	return result;
}

TRUST_AUTHORITY_STATUS get_token(trust_authority_connector *connector,
		response_headers *resp_headers,
		token *token,
		policies *policies,
		evidence *evidence,
		nonce *nonce,
		const char *request_id)
{
	int result = STATUS_OK;
	appraisal_request request = {0};
	char *json = NULL;
	char url[API_URL_MAX_LEN + 1] = {0};
	char *response = NULL;
	char *headers = NULL;
	CURLcode status = CURLE_OK;

	if (NULL == connector)
	{
		return STATUS_NULL_CONNECTOR;
	}

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == evidence)
	{
		return STATUS_NULL_EVIDENCE;
	}

	if (NULL == evidence->evidence)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (evidence->evidence_len > MAX_EVIDENCE_LEN)
	{
		ERROR("Error: Evidence data size %d exceeds maximum length %d\n", evidence->evidence_len, MAX_EVIDENCE_LEN);
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == nonce)
	{
		return STATUS_NULL_NONCE;
	}

	strncat(url, connector->api_url, API_URL_MAX_LEN);
	strncat(url, "/appraisal/v1/attest", API_URL_MAX_LEN);
	DEBUG("Token url: %s\n", url);
	
	request.quote_len = evidence->evidence_len;
	request.quote = evidence->evidence;
	request.verifier_nonce = nonce;
	request.runtime_data_len = evidence->user_data_len;
	request.runtime_data = evidence->user_data;
	request.policy_ids = policies;
	request.event_log_len = evidence->event_log_len;
	request.event_log = evidence->event_log;
	//Marshal the request in JSON form to be sent to Intel Trust Authority
	result = json_marshal_appraisal_request(&request, &json);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to marshal appraisal request\n");
		goto ERROR;
	}

	//Get token from Intel Trust Authority
	status = post_request(url, connector->api_key, ACCEPT_APPLICATION_JSON, request_id, CONTENT_TYPE_APPLICATION_JSON, json, &response, &headers, connector->retries);
	if (NULL == response || CURLE_OK != status)
	{
		ERROR("Error: GET request to %s failed", url);
		result = STATUS_POST_TOKEN_ERROR ;
		goto ERROR;
	}

	//Unmarshal token as per struct token.
	result = json_unmarshal_token(token, (const char *)response);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to unmarshal token\n");
		goto ERROR;
	}

	//Fetch all the headers
	size_t size = strlen(headers);
	resp_headers->headers = (char *)calloc(size + 1, sizeof(char));
	if (NULL == resp_headers->headers)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	memcpy(resp_headers->headers, headers, size);

ERROR:

	if (json)
	{
		free(json);
		json = NULL;
	}
	return result;
}

// This method detects malformed URLs
int is_valid_url(const char *url)
{
	int ret;
	regex_t regex;
	ret = regcomp(&regex, "^(https)://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\\s%]*)*$", REG_EXTENDED);
	if (ret)
	{
		ERROR("Error: Could not compile regex\n");
		return ret;
	}
	ret = regexec(&regex, url, 0, NULL, 0);
	regfree(&regex);
	if (ret)
	{
		ERROR("Error: Invalid URL\n");
		return ret;
	}

	return ret;
}

int is_valid_uuid(const char *uuid_str)
{
	// Regular expression pattern for UUID format
	const char *pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

	regex_t regex;
	int ret;

	ret = regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB);
	if (ret)
	{
		ERROR("Error: Could not compile regex.\n");
		return ret;
	}

	ret = regexec(&regex, uuid_str, 0, NULL, 0);
	regfree(&regex);
	if (ret)
	{
		ERROR("Error: Regex match failed or No match found.\n");
		return ret;
	}

	return ret;
}

// Validate format of api_key
TRUST_AUTHORITY_STATUS is_valid_api_key(const char *api_key)
{
	size_t base64_input_length = 0, output_length = 0;
	unsigned char *buf = NULL;

	base64_input_length = strlen(api_key);
	output_length = (base64_input_length / 4) * 3; // Estimate the output length
	buf = (unsigned char *)calloc(output_length + 1, sizeof(unsigned char));
	if (NULL == buf)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	if (BASE64_SUCCESS != base64_decode(api_key, base64_input_length, buf, &output_length))
	{
		free(buf);
		buf = NULL;
		return STATUS_INVALID_API_KEY;
	}
	// freeing buffer upon success
	free(buf);
	buf = NULL;

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS get_token_signing_certificate(const char *jwks_url,
		char **jwks,
		const int retry_max,
		const int retry_wait_time)

{
	if ( jwks == NULL && jwks_url == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	CURLcode status = CURLE_OK;
	char *header = NULL;

	retry_config *retries = (retry_config *)calloc(1, sizeof(retry_config));
	if (NULL == retries)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	if (retry_max != 0)
	{
		retries->retry_max = retry_max;
	}
	if (retry_wait_time != 0)
	{
		retries->retry_wait_time = retry_wait_time;
	}
	status = get_request(jwks_url, NULL, ACCEPT_APPLICATION_JSON, NULL, NULL, jwks, &header, retries);
	if (CURLE_OK != status || *jwks == NULL)
	{
		return STATUS_GET_SIGNING_CERT_ERROR;
	}
	DEBUG("\nRetrieved token signing certificate : \n%s", *jwks);

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS parse_token_header_for_kid(token *token,
		const char **token_kid)
{
	char *substring = NULL;
	size_t substring_length = 0;
	size_t base64_input_length = 0, output_length = 0;
	unsigned char *buf = NULL;
	json_error_t error;
	json_t *js, *js_val;
	const char *val = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_OK;
	int include_char = 0;
	char equal='=';

	// // Check if token or token jwt pointer is NULL
	if (token == NULL || token->jwt == NULL)
	{
		return STATUS_NULL_TOKEN;
	}
	char *period_pos = strchr(token->jwt, '.');
	if (NULL == period_pos)
	{
		return STATUS_TOKEN_INVALID_ERROR;
	}
	// Calculate the length of the substring
	substring_length = period_pos - token->jwt;

	if((substring_length % 4) != 0)
	{
		substring_length += 1;
		if((substring_length % 4) != 0)
		{
			return STATUS_TOKEN_INVALID_ERROR;
		}
		include_char = 1;
	}

	// Allocate memory for the substring
	substring = calloc(1, (substring_length + 1) * sizeof(char));
	if (NULL == substring)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	// Copy the substring
	if (include_char == 0) 
	{
		memcpy(substring, token->jwt, substring_length);
	}
	else
	{
		memcpy(substring, token->jwt, (substring_length-1));
		memcpy(substring+(substring_length-1), &equal, 1);
	}

	// Do base64 decode.
	base64_input_length = substring_length;
	output_length = (base64_input_length / 4) * 3; // Estimate the output length
	buf = (unsigned char *)calloc(1, (output_length + 1) * sizeof(unsigned char));
	if (NULL == buf)
	{
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	if (BASE64_SUCCESS != base64_decode(substring, base64_input_length, buf, &output_length))
	{
		status = STATUS_TOKEN_DECODE_ERROR;
		goto ERROR;
	}
	// load the decoded header to json
	js = json_loads((const char *)buf, 0, &error);
	if (!js)
	{
		status = STATUS_TOKEN_DECODE_ERROR;
		goto ERROR;
	}

	js_val = json_object_get(js, "kid");
	if (js_val == NULL)
	{
		status = STATUS_TOKEN_KID_NULL_ERROR;
		goto ERROR;
	}
	if (json_typeof(js_val) == JSON_STRING)
	{
		val = json_string_value(js_val);
	}
	else
	{
		status = STATUS_INVALID_KID_ERROR;
		goto ERROR;
	}

	*token_kid = val;

ERROR:
	if (buf != NULL)
	{
		free(buf);
		buf = NULL;
	}
	if (substring != NULL)
	{
		free(substring);
		substring = NULL;
	}

	return status;
}

TRUST_AUTHORITY_STATUS generate_pubkey_from_exponent_and_modulus(const char *exponent,
		const char *modulus,
		EVP_PKEY **pubkey)
{
	BIGNUM *n = bignum_base64_decode(modulus);
	BIGNUM *e = bignum_base64_decode(exponent);

	if (!e || !n)
	{
		ERROR("Error: Invalid encoding for public exponent or modulus\n");
		return STATUS_GENERATE_PUBKEY_ERROR;
	}

	EVP_PKEY *pRsaKey = EVP_PKEY_new();
	RSA *rsa = RSA_new();

	if (!RSA_set0_key(rsa, n, e, NULL))
	{
		ERROR("Error: Failed to set RSA key components");
		// free the rsa key components memory
		goto ERROR;
	}
	// setting key type to EVP_PKEY_RSA_PSS as it follows PS384 alg
	EVP_PKEY_assign(pRsaKey, EVP_PKEY_RSA_PSS, rsa);
	if (pRsaKey != NULL)
	{
		*pubkey = pRsaKey;
		return STATUS_OK;
	}

ERROR:
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);
	if (rsa)
		RSA_free(rsa);
	return STATUS_GENERATE_PUBKEY_ERROR;
}

TRUST_AUTHORITY_STATUS format_pubkey(EVP_PKEY *pkey,
		const char **formatted_pub_key)
{
	TRUST_AUTHORITY_STATUS status = STATUS_OK;
	// Create a BIO to hold the key data
	BIO *bio = BIO_new(BIO_s_mem());
	if (NULL == bio)
	{
		return STATUS_FORMAT_PUBKEY_ERROR;
	}
	// Write the key data to the BIO
	if (!PEM_write_bio_PUBKEY(bio, pkey))
	{
		status = STATUS_FORMAT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Determine the length of the key data
	size_t key_len = BIO_pending(bio);

	// Allocate memory for the mutable buffer, including space for null terminator
	char *key_str = (char *)malloc((key_len + 1) * sizeof(char));
	if (NULL == key_str)
	{
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	// Read the key data from the BIO into the mutable buffer
	if (BIO_read(bio, key_str, key_len) < 0)
	{
		free(key_str);
		key_str = NULL;
		status = STATUS_FORMAT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Null-terminate the mutable buffer
	key_str[key_len] = '\0';

	// Create a const char* to hold the converted key
	*formatted_pub_key = strdup(key_str);

ERROR:
	// Cleanup
	if (key_str)
	{
		free(key_str);
		key_str = NULL;
	}
	BIO_free(bio);

	return status;
}

TRUST_AUTHORITY_STATUS connector_free(trust_authority_connector *connector)
{
	if (NULL != connector)
	{
		free(connector);
		connector = NULL;
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS nonce_free(nonce *nonce)
{
	if (NULL != nonce)
	{
		if (NULL != nonce->val)
		{
			free(nonce->val);
			nonce->val = NULL;
		}

		if (NULL != nonce->iat)
		{
			free(nonce->iat);
			nonce->iat = NULL;
		}

		if (NULL != nonce->signature)
		{
			free(nonce->signature);
			nonce->signature = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS token_free(token *token)
{
	if (token)
	{
		if (token->jwt)
		{
			free(token->jwt);
			token->jwt = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_free(evidence *evidence)
{
	if (NULL != evidence)
	{
		if (NULL != evidence->evidence)
		{
			free(evidence->evidence);
			evidence->evidence = NULL;
		}

		if (NULL != evidence->user_data)
		{
			free(evidence->user_data);
			evidence->user_data = NULL;
		}

		if (NULL != evidence->event_log)
		{
			free(evidence->event_log);
			evidence->event_log = NULL;
		}
	}

	return STATUS_OK;
}
