/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <nvgpu_adapter.h>
#include <tdx_adapter.h>
#include <evidence_builder.h>
#include <token_provider.h>
#include <token_verifier.h>
#include <api.h>

#include <log.h>
#include <jwt.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <assert.h>

#define ENV_TRUSTAUTHORITY_API_URL "TRUSTAUTHORITY_API_URL"
#define ENV_TRUSTAUTHORITY_BASE_URL "TRUSTAUTHORITY_BASE_URL"
#define ENV_TRUSTAUTHORITY_API_KEY "TRUSTAUTHORITY_API_KEY"
#define ENV_TRUSTAUTHORITY_POLICY_ID "TRUSTAUTHORITY_POLICY_ID"
#define ENV_RETRY_MAX "RETRY_MAX"
#define ENV_RETRY_WAIT_TIME "RETRY_WAIT_TIME"
#define ENV_REQUEST_ID "REQUEST_ID"
#define ENV_TOKEN_SIG_ALG "TOKEN_SIGNING_ALG"
#define ENV_POLICY_MUST_MATCH "POLICY_MUST_MATCH"
#define ENCLAVE_PATH "enclave.signed.so"

int main(int argc, char *argv[])
{
	int status = 0, result;
	trust_authority_connector *connector = NULL;
	evidence_builder *builder = NULL;
	token token = {0};
	json_t *nvgpu_evi_jsonobj = NULL;
	json_t *evidence = NULL;
	nonce nonce = {0};
	response_headers headers = {0};
	evidence_adapter *nvgpu_adapter = NULL;
	evidence_adapter *tdx_adapter = NULL;
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_ids = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *token_signing_alg_str = getenv(ENV_TOKEN_SIG_ALG);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *policy_must_match_str = getenv(ENV_POLICY_MUST_MATCH);
	char *request_id = getenv(ENV_REQUEST_ID);
	bool policy_must_match;
	int retry_max, retry_wait_time = 0;
	jwt_t *parsed_token = NULL;
	builder_opts opts = {0};
	get_nonce_args nonce_args = {0};
	char cloud_provider[CLOUD_PROVIDER_MAX_LEN] = {0};

	if (NULL == ta_api_url || !strlen(ta_api_url))
	{
		ERROR("ERROR: Environment variable is required %s\n", ENV_TRUSTAUTHORITY_API_URL);
		return 1;
	}

	if (NULL == ta_base_url || !strlen(ta_base_url))
	{
		ERROR("ERROR: Environment variable is required %s\n", ENV_TRUSTAUTHORITY_BASE_URL);
		return 1;
	}

	if (NULL == ta_key || !strlen(ta_key))
	{
		ERROR("ERROR: Environment variable is required %s\n", ENV_TRUSTAUTHORITY_API_KEY);
		return 1;
	}

	if (NULL == retry_max_str)
	{
		retry_max = DEFAULT_RETRY_MAX;
	}
	else
	{
		retry_max = atoi(retry_max_str);
		if (0 == retry_max)
		{
			ERROR("ERROR: Invalid RETRY_MAX format. RETRY_MAX should be an integer.\n");
			return 1;
		}
	}

	if (NULL == retry_wait_time_str)
	{
		retry_wait_time = DEFAULT_RETRY_WAIT_TIME;
	}
	else
	{
		retry_wait_time = atoi(retry_wait_time_str);
		if (0 == retry_wait_time)
		{
			ERROR("ERROR: Invalid RETRY_WAIT_TIME format. RETRY_WAIT_TIME should be an integer.\n");
			return 1;
		}
		
	}

	if (0 != is_valid_url(ta_base_url))
	{
		ERROR("ERROR: Invalid TRUSTAUTHORITY_BASE_URL format\n");
		return 1;
	}


	if (STATUS_OK != is_valid_token_sigining_alg(token_signing_alg_str))
	{
		ERROR("ERROR: Unsupported Token Signing Algorithm, supported algorithms are RS256/PS384\n");
		return 1;
	}


	if (STATUS_OK != validate_and_get_policy_must_match(policy_must_match_str, &policy_must_match))
	{
		ERROR("ERROR: Unsupported Policy Match Value, supported values are true/false\n");
		return 1;
	}

	if (request_id != NULL && 0 != validate_request_id(request_id))
	{
		ERROR("ERROR: Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \\");
		return 1;
	}

	LOG("Info: Connecting to %s\n", ta_api_url);

	unsigned char* user_data = NULL;
	int user_data_len = 0;

	status = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create trust authority connector: 0x%04x\n", status);
		goto MAIN_ERROR;
	}

	status = nvgpu_adapter_new(&nvgpu_adapter);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create NVGPU Adapter: 0x%04x\n", status);
		goto MAIN_ERROR;
	}

#ifdef AZURE_TDX
	strncat(cloud_provider, "azure", 5);
	result = azure_tdx_adapter_new(&tdx_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Azure TDX Adapter: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

#else
	result = tdx_adapter_new(&tdx_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create TDX Adapter: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

#endif

	nonce_args.request_id = request_id;

	result = get_nonce(connector, &nonce, &nonce_args, &headers);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to get Trust Authority nonce 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	opts.nonce = &nonce;
	opts.user_data = user_data;
	opts.user_data_len = user_data_len;
	opts.policy_ids = policy_ids;
	opts.policy_must_match = policy_must_match;
	opts.token_signing_alg = token_signing_alg_str;
	result = evidence_builder_new(&builder, &opts);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create evidence builder: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	result = evidence_builder_add_adapter(builder, tdx_adapter);
	if(STATUS_OK != result)
	{
		ERROR("ERROR: Failed to add TDX adapter to builder: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	result = evidence_builder_add_adapter(builder, nvgpu_adapter);
	if(STATUS_OK != result)
	{
		ERROR("ERROR: Failed to add NVGPU adapter to builder: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	evidence = json_object();
	result = evidence_builder_get_evidence(builder, evidence);
	if(STATUS_OK != result)
	{
		ERROR("ERROR: Failed to get evidence from builder: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	char *json_str_forbuild = json_dumps(evidence, JSON_INDENT(4));
	if(json_str_forbuild == NULL)
	{
		ERROR("ERROR: Failed to serialize composite evidence to json string\n");
		goto MAIN_ERROR;
	}
	LOG("Info: Built Evidence: %s\n", json_str_forbuild);
	free(json_str_forbuild);

	result = attest_evidence(connector, &headers, &token, evidence, request_id, cloud_provider);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	LOG("Info: Intel Trust Authority Token: %s\n", token.jwt);
	LOG("Info: Headers returned: %s\n", headers.headers);

	result = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", result);
		goto MAIN_ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: Parsed token : ");
	jwt_dump_fp(parsed_token, stdout, 1);

MAIN_ERROR:

	nvgpu_adapter_free(nvgpu_adapter);
	tdx_adapter_free(tdx_adapter);
	evidence_builder_free(builder);
	nonce_free(&nonce);
	response_headers_free(&headers);
	connector_free(connector);
	token_free(&token);
	jwt_free(parsed_token);
	return status;
}
