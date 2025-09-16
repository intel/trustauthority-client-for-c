/*
 * Copyright (C) 2023-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <types.h>
#include <json.h>
#include "api.h"
#include "appraisal_request.h"
#include "rest.h"
#include <log.h>
#include <base64.h>
#include <regex.h>

TRUST_AUTHORITY_STATUS trust_authority_connector_new(trust_authority_connector **connector,
		const char *api_key,
		const char *api_url,
		const int retry_max,
		const int retry_wait_time)
{
	TRUST_AUTHORITY_STATUS status = STATUS_OK;

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
		ERROR("Invalid Trust Authority Api key, must be lesser than %d in length\n", API_KEY_MAX_LEN);
		return STATUS_INVALID_API_KEY;
	}

	int api_url_len = strnlen(api_url, API_URL_MAX_LEN + 1);
	if (api_url_len > API_URL_MAX_LEN)
	{
		ERROR("Invalid Trust Authority Api URL, must be lesser than %d in length\n", API_URL_MAX_LEN);
		return STATUS_INVALID_API_URL;
	}

	// Validate format of api_url
	if (0 != is_valid_url(api_url))
	{
		ERROR("Invalid Trust Authority Api URL\n");
		return STATUS_INVALID_API_URL;
	}
	// Validate format of api_key
	status = is_valid_api_key(api_key);
	if (STATUS_OK != status)
	{
		ERROR("Invalid Trust Authority Api key\n");
		return status;
	}

	// Handling trailing slashes in api_url
	char mutable_api_url[API_URL_MAX_LEN + 1];
	strncpy(mutable_api_url, api_url, api_url_len);
	mutable_api_url[api_url_len] = '\0'; // Ensure null termination
	if (mutable_api_url[api_url_len - 1] == '/')
	{
		mutable_api_url[api_url_len - 1] = '\0';
	}
	api_url = mutable_api_url; // Update api_url to point to the mutable copy

	*connector = (trust_authority_connector *)calloc(1, sizeof(trust_authority_connector));
	if (NULL == *connector)
	{
		return STATUS_ALLOCATION_ERROR;
	}
	(*connector)->retries = (retry_config *)calloc(1, sizeof(retry_config));
	if (NULL == (*connector)->retries)
	{
		free(*connector);
		*connector = NULL;
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
		get_nonce_args *args,
		response_headers *resp_headers)
{
	int result = STATUS_OK;
	char *response = NULL;
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
	strncat(url, "/appraisal/v2/nonce", API_URL_MAX_LEN);
	DEBUG("Nonce url: %s\n", url);

	//Get nonce from Intel Trust Authority
	int response_length = 0;
	status = get_request(url, connector->api_key, ACCEPT_APPLICATION_JSON, args->request_id, NULL, &response ,&response_length, &headers, connector->retries);
	if (NULL == response || CURLE_OK != status)
	{
		ERROR("Error: GET request to %s failed", url);
		result = STATUS_GET_NONCE_ERROR;
		goto ERROR;
	}

	//Unmarshal nonce as per struct nonce.
	result = json_unmarshal_nonce(nonce, response);
	if (STATUS_OK != result)
	{
		ERROR("Error: Unmarshalling Nonce - %d\n", result);
		goto ERROR;
	}
	//Fetch all the headers recieved.
	size_t size = strlen(headers);
	resp_headers->headers = (char *)calloc(size + 1, sizeof(char));
	if (NULL == resp_headers->headers)
	{
		result = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(resp_headers->headers, headers, size);

ERROR:

	if (response)
	{
		free(response);
		response = NULL;
	}
	if (headers)
	{
		free(headers);
		headers = NULL;
	}
	return result;
}

TRUST_AUTHORITY_STATUS get_token(trust_authority_connector *connector,
		response_headers *resp_headers,
		token *token,
		get_token_args *args,
		char *attestation_endpoint)
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
	if (NULL == args)
	{
		return STATUS_NULL_ARGS;
	}

	if (NULL == args->evidence)
	{
		return STATUS_NULL_EVIDENCE;
	}

	if (NULL == args->evidence->evidence)
	{
		return STATUS_NULL_EVIDENCE;
	}
	if (args->evidence->evidence_len > MAX_EVIDENCE_LEN)
	{
		ERROR("Error: Evidence data size %d exceeds maximum length %d\n", args->evidence->evidence_len, MAX_EVIDENCE_LEN);
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == args->nonce)
	{
		return STATUS_NULL_NONCE;
	}

	strncat(url, connector->api_url, API_URL_MAX_LEN);
	strncat(url, attestation_endpoint, API_URL_MAX_LEN);
	DEBUG("Token url: %s\n", url);
	
	request.quote_len = args->evidence->evidence_len;
	request.quote = args->evidence->evidence;
	request.verifier_nonce = args->nonce;
	request.runtime_data_len = args->evidence->runtime_data_len;
	request.runtime_data = args->evidence->runtime_data;
	request.user_data_len = args->evidence->user_data_len;
	request.user_data = args->evidence->user_data;
	request.policy_ids = args->policies;
	request.event_log_len = args->evidence->event_log_len;
	request.event_log = args->evidence->event_log;
	request.token_signing_alg = args->token_signing_alg;
	request.policy_must_match = args->policy_must_match;
	//Marshal the request in JSON form to be sent to Intel Trust Authority
	result = json_marshal_appraisal_request(&request, &json);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to marshal appraisal request\n");
		goto ERROR;
	}

	//Get token from Intel Trust Authority
	int response_length = 0;
	status = post_request(url, connector->api_key, ACCEPT_APPLICATION_JSON, args->request_id, CONTENT_TYPE_APPLICATION_JSON, json, &response, &response_length, &headers, connector->retries);
	if (NULL == response || CURLE_OK != status)
	{
		ERROR("Error: POST request to %s failed", url);
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
		result = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(resp_headers->headers, headers, size);

ERROR:

	if (json)
	{
		free(json);
		json = NULL;
	}
	if (response)
	{
		free(response);
		response = NULL;
	}
	if (headers)
	{
		free(headers);
		headers = NULL;
	}
	return result;
}

TRUST_AUTHORITY_STATUS attest_evidence(trust_authority_connector *connector,
		response_headers *resp_headers,
		token *token,
		json_t *evidence,
		char *request_id,
		char *cloud_provider)
{
	int result = STATUS_OK;
	char *json = NULL;
	char url[2*API_URL_MAX_LEN] = {0};
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

	snprintf(url, sizeof(url), "%s%s", connector->api_url, "/appraisal/v2/attest");
	if (strncmp(cloud_provider, "", 1) != 0) {
		snprintf(url+strnlen(url, sizeof(url)), sizeof(url), "/%s", cloud_provider);
	}
	DEBUG("Token url: %s\n", url);

	//Marshal the request in JSON form to be sent to Intel Trust Authority
	json = json_dumps(evidence, JSON_INDENT(4));
	if (NULL == json)
	{
		ERROR("Error: Failed to serialize appraisal request\n");
		result = STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	//Get token from Intel Trust Authority
	int response_length = 0;
	status = post_request(url, connector->api_key, ACCEPT_APPLICATION_JSON, request_id, CONTENT_TYPE_APPLICATION_JSON, json, &response, &response_length, &headers, connector->retries);
	if (NULL == response || CURLE_OK != status)
	{
		ERROR("Error: POST request to %s failed", url);
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
		result = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(resp_headers->headers, headers, size);

ERROR:

	if (json)
	{
		free(json);
		json = NULL;
	}
	if (response)
	{
		free(response);
		response = NULL;
	}
	if (headers)
	{
		free(headers);
		headers = NULL;
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

TRUST_AUTHORITY_STATUS is_valid_token_sigining_alg(const char *input)
{
	if (input == NULL || strcmp(input, "") == 0)
	{
		return STATUS_OK;
	}
	if ((strcmp(input, PS384) == 0) || (strcmp(input, RS256) == 0)){
		return STATUS_OK;
	}
	return STATUS_INVALID_TOKEN_SIGNING_ALG;
}

TRUST_AUTHORITY_STATUS validate_and_get_policy_must_match(const char *input, bool *policy_must_match)
{
	if (input == NULL || (strcmp(input, "false") == 0))
	{
		*policy_must_match = false;
	}
	else if (strcmp(input, "true") == 0)
	{ 
		*policy_must_match = true;
	}
	else 
	{
		return STATUS_INVALID_POLICY_MUST_MATCH; 
	}
	return STATUS_OK;
}

int validate_request_id(const char *req_id)
{
	if (req_id == NULL || strcmp(req_id, "") == 0)
	{
		return 0;
	}

	// Define the regex pattern for allowed characters
	const char *pattern = "^[a-zA-Z0-9_ /.-]{1,128}$";
	regex_t regex;
	int ret = regcomp(&regex, pattern, REG_EXTENDED);
	if (ret) {
		ERROR("Error: Could not compile regex\n");
		return ret;
	}

	// Execute the regex
	ret = regexec(&regex, req_id, 0, NULL, 0);
	regfree(&regex);
	if (ret)
	{
		ERROR("Error: Invalid REQUEST_ID\n");
		return ret;
	}

	return 0;
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

TRUST_AUTHORITY_STATUS get_token_signing_certificate(const char *base_url,
		char **jwks,
		const int retry_max,
		const int retry_wait_time)
{
	CURLcode status = CURLE_OK;
	char *header = NULL;
	char jwks_url[API_URL_MAX_LEN + 1] = {0};
	TRUST_AUTHORITY_STATUS ret = STATUS_OK;
	if (base_url == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (jwks == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	retry_config *retries = NULL;
	retries = (retry_config *)calloc(1, sizeof(retry_config));
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

	strncat(jwks_url, base_url, API_URL_MAX_LEN);
	strncat(jwks_url, "/certs", API_URL_MAX_LEN);
	DEBUG("JWKS url: %s\n", jwks_url);

	//Get JWKS from Intel Trust Authority
	int jwks_length = 0;
	status = get_request(jwks_url, NULL, ACCEPT_APPLICATION_JSON, NULL, NULL, jwks, &jwks_length, &header, retries);
	if (CURLE_OK != status || *jwks == NULL)
	{
		ERROR("Error: GET request to %s failed", jwks_url);
		ret = STATUS_GET_SIGNING_CERT_ERROR;
	}

	free(retries);
	retries = NULL;
	if (NULL != header)
	{
		free(header);
		header = NULL;
	}
	return ret;
}

TRUST_AUTHORITY_STATUS connector_free(trust_authority_connector *connector)
{
	if (NULL != connector)
	{
		if (NULL != connector->retries)
		{
			free(connector->retries);
			connector->retries = NULL;
		}
		free(connector);
		connector = NULL;
	}
	return STATUS_OK;
}
