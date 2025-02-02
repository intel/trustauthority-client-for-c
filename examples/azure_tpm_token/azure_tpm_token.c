/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <tdx_adapter.h>
#include <tpm_adapter.h>
#include <token_verifier.h>
#include <evidence_builder.h>
#include <jwt.h>
#include <log.h>
#include <api.h>

#define ENV_TRUSTAUTHORITY_API_URL "TRUSTAUTHORITY_API_URL"
#define ENV_TRUSTAUTHORITY_BASE_URL "TRUSTAUTHORITY_BASE_URL"
#define ENV_TRUSTAUTHORITY_API_KEY "TRUSTAUTHORITY_API_KEY"
#define ENV_TRUSTAUTHORITY_POLICY_ID "TRUSTAUTHORITY_POLICY_ID"
#define ENV_RETRY_MAX "RETRY_MAX"
#define ENV_RETRY_WAIT_TIME "RETRY_WAIT_TIME"
#define ENV_REQUEST_ID "REQUEST_ID"
#define ENV_TOKEN_SIG_ALG "TOKEN_SIGNING_ALG"
#define ENV_POLICY_MUST_MATCH "POLICY_MUST_MATCH"
#define ENV_TPM_WITH_IMA_LOGS "TPM_WITH_IMA_LOGS"
#define ENV_TPM_WITH_UEFI_LOGS "TPM_WITH_UEFI_LOGS"
#define ENV_TPM_WITH_PCR_SELECTIONS "TPM_WITH_PCR_SELECTIONS"

#define AZURE_AK_HANDLE 0x81000003

int get_env_bool(const char *env_var)
{
	char *env_val = getenv(env_var);
	if (env_val == NULL)
	{
		return 0;
	}

	return (strcasecmp(env_val, "true") == 0);
}

int main(int argc, char *argv[])
{
	int result;
	trust_authority_connector *connector = NULL;
	evidence_adapter *tdx_adapter = NULL;
	evidence_adapter *tpm_adapter = NULL;
	evidence_builder *builder = NULL;
	nonce nonce = {0};
	token token = {0};
	json_t *evidence = NULL;
	response_headers headers = {0};
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_ids = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *request_id = getenv(ENV_REQUEST_ID);
	char *token_signing_alg_str = getenv(ENV_TOKEN_SIG_ALG);
	char *policy_must_match_str = getenv(ENV_POLICY_MUST_MATCH);
	char *with_pcr_selection_str = getenv(ENV_TPM_WITH_PCR_SELECTIONS);
	int retry_max, retry_wait_time = 0;
	bool policy_must_match;
	bool with_ima_logs = get_env_bool(ENV_TPM_WITH_IMA_LOGS);
	bool with_uefi_logs = get_env_bool(ENV_TPM_WITH_UEFI_LOGS);

	// Store Parsed Token
	jwt_t *parsed_token = NULL;
	get_nonce_args nonce_args = {0};
	builder_opts opts = {0};

	if (NULL == ta_api_url || !strlen(ta_api_url))
	{
		ERROR("ERROR: %s - environment variable is required\n", ENV_TRUSTAUTHORITY_API_URL);
		return 1;
	}

	if (NULL == ta_base_url || !strlen(ta_base_url))
	{
		ERROR("ERROR: %s - environment variable is required\n", ENV_TRUSTAUTHORITY_BASE_URL);
		return 1;
	}

	if (NULL == ta_key || !strlen(ta_key))
	{
		ERROR("ERROR: %s - environment variable is required\n", ENV_TRUSTAUTHORITY_API_KEY);
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

	if (token_signing_alg_str != NULL && STATUS_OK != is_valid_token_sigining_alg(token_signing_alg_str))
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

	LOG("Info: connecting to %s\n", ta_api_url);
	result = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Trust Authority Connector: 0x%04x\n", result);
		goto DONE;
	}

	result = azure_tdx_adapter_new(&tdx_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Azure TDX Adapter: 0x%04x\n", result);
		goto DONE;
	}

	result = tpm_adapter_new(&tpm_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Azure TPM Adapter: 0x%04x\n", result);
		goto DONE;
	}

	tpm_with_ak_handle(tpm_adapter, AZURE_AK_HANDLE);
	tpm_with_ima_log(tpm_adapter, with_ima_logs);
	tpm_with_uefi_log(tpm_adapter, with_uefi_logs);
	tpm_with_pcr_selections(tpm_adapter, with_pcr_selection_str);

/*
	// sample code on calling tpm_get_evidence api directly, with evidence returned in the json format enclosure as json_object
	evidence = json_object();
	result = tpm_get_evidence(tpm_adapter->ctx, evidence, NULL, user_data, user_data_len);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to collect TPM evidence from Azure adapter 0x%04x\n", result);
		goto DONE;
	}

	// Serialize the JSON object to a string and print it
	char *json_string = json_dumps(evidence, JSON_INDENT(4));
	if(json_string == NULL)
	{
		ERROR("ERROR: Failed to serialize evidence to json string\n");
		goto DONE;
	}
	LOG("Info: Evidence: %s\n", json_string);
	json_decref(evidence);
	free(json_string);
*/

	nonce_args.request_id = request_id;
	result = get_nonce(connector, &nonce, &nonce_args, &headers);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to get Trust Authority nonce 0x%04x\n", result);
		goto DONE;
	}

	opts.nonce = &nonce;
	opts.policy_ids = policy_ids;
	opts.policy_must_match = policy_must_match;
	opts.token_signing_alg = token_signing_alg_str;
	result = evidence_builder_new(&builder, &opts);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create evidence builder: 0x%04x\n", result);
		goto DONE;
	}

	result = evidence_builder_add_adapter(builder, tdx_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to add tdx adapter to builder: 0x%04x\n", result);
		goto DONE;
	}

	result = evidence_builder_add_adapter(builder, tpm_adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to add tpm adapter to builder: 0x%04x\n", result);
		goto DONE;
	}

	evidence = json_object();
	result = evidence_builder_get_evidence(builder, evidence);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to get evidence from builder: 0x%04x\n", result);
		goto DONE;
	}

	// Serialize the JSON object to a string and print it
	char *json_string = json_dumps(evidence, JSON_INDENT(4));
	if (json_string == NULL)
	{
		ERROR("ERROR: Failed to serialize evidence to json string\n");
		goto DONE;
	}
	LOG("Info: Evidence: %s\n", json_string);
	free(json_string);

	result = attest_evidence(connector, &headers, &token, evidence, request_id, "azure");
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", result);
		goto DONE;
	}
	LOG("Info: Trust Authority Token: %s\n", token.jwt);
	LOG("Info: Headers returned: %s\n", headers.headers);

	result = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", result);
		goto DONE;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: Parsed token: ");
	jwt_dump_fp(parsed_token, stdout, 1);

DONE:

	if (NULL != evidence)
	{
		json_decref(evidence);
		evidence = NULL;
	}
	if (NULL != parsed_token)
	{
		jwt_free(parsed_token);
	}

	response_headers_free(&headers);
	evidence_builder_free(builder);
	tdx_adapter_free(tdx_adapter);
	tpm_adapter_free(tpm_adapter);
	connector_free(connector);
	token_free(&token);
	nonce_free(&nonce);
	return result;
}
