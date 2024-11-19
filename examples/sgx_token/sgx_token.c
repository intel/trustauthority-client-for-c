#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <sgx_adapter.h>
#include <token_provider.h>
#include <token_verifier.h>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "utils.h"
#include <log.h>
#include <jwt.h>

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
	int status = 0;
	trust_authority_connector *connector = NULL;
	token token = {0};
	evidence evidence = {0};
	response_headers headers = {0};
	evidence_adapter *adapter = NULL;
	policies policies = {0};
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_id = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *token_sign_alg_str = getenv(ENV_TOKEN_SIG_ALG);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *policy_must_match_str = getenv(ENV_POLICY_MUST_MATCH);
	char *request_id = getenv(ENV_REQUEST_ID);
	bool policy_must_match;
	int retry_max, retry_wait_time = 0;
	// Create enclave and get id
	sgx_enclave_id_t eid = 0;
	// Enclave public key
	uint32_t key_size;
	uint8_t *key_buf = NULL;
	// Store Parsed Token
	jwt_t *parsed_token = NULL;
	collect_token_args token_args = {0};

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

	if (policy_id != NULL && 0 != is_valid_uuid(policy_id))
	{
		ERROR("ERROR: Invalid TRUSTAUTHORITY_POLICY_ID format, must be UUID");
		return 1;
	}

	if (0 != is_valid_url(ta_base_url))
	{
		ERROR("ERROR: Invalid TRUSTAUTHORITY_BASE_URL format\n");
		return 1;
	}


	if (token_sign_alg_str != NULL && STATUS_OK != is_valid_token_sigining_alg(token_sign_alg_str))
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

	char *ids[] = {policy_id};
	policies.ids = ids;
	policies.count = 1;

	LOG("Info: Connecting to %s\n", ta_api_url);

	status = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create trust authority connector: 0x%04x\n", status);
		goto ERROR;
	}

	status = sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);
	if (0 != status)
	{
		ERROR("ERROR: Failed in sgx_create_enclave() 0x%04x\n", status);
		goto ERROR;
	}

	status = get_public_key(eid, &key_buf, &key_size);
	if (0 != status)
	{
		ERROR("ERROR: Failed in get_public_key(): 0x%04x\n", status);
		goto ERROR;
	}

	status = sgx_adapter_new(&adapter, eid, enclave_create_report);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create SGX Adapter: 0x%04x\n", status);
		goto ERROR;
	}

	status = sgx_collect_evidence(adapter->ctx, &evidence, NULL, key_buf, key_size);
	if (STATUS_OK != status)
	{
		ERROR("Error: Failed to collect evidence from adapter 0x%04x\n", status);
		goto ERROR;
	}

	int output_length = ((evidence.evidence_len + 2) / 3) * 4 + 1;
	char *b64 = NULL;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		ERROR("Error: Failed to allocate memory for base64 encoded quote")
		goto ERROR;
	}
	status = base64_encode(evidence.evidence, evidence.evidence_len, b64, output_length, 0);
	if (BASE64_SUCCESS != status)
	{
		ERROR("Error: Failed to base64 encode quote 0x%04x\n", status)
		goto ERROR;
	}
	LOG("Info: quote: %s\n", b64);

	memset(b64, 0, evidence.evidence_len);
	output_length = ((evidence.runtime_data_len + 2) / 3) * 4 + 1;
	status = base64_encode(evidence.runtime_data, evidence.runtime_data_len, b64, output_length, 0);
	if (BASE64_SUCCESS != status)
	{
		ERROR("Error: Failed to base64 encode user-data 0x%04x\n", status)
		goto ERROR;
	}
	LOG("Info: user-data: %s\n", b64);
	token_args.policies = &policies;
	token_args.request_id = request_id;
	token_args.token_signing_alg = token_sign_alg_str;
	token_args.policy_must_match = policy_must_match;

	status = collect_token(connector, &headers, &token, &token_args, adapter, key_buf, key_size);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", status);
		goto ERROR;
	}

	LOG("Info: trust authority token: %s\n", token.jwt);
	LOG("Info: Headers returned: %s\n",headers.headers);

	status = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", status);
		goto ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: Parsed token : ");
	jwt_dump_fp(parsed_token, stdout, 1);

ERROR:

	if (0 != eid)
	{
		sgx_destroy_enclave(eid);
	}
	if (NULL != key_buf)
	{
		free(key_buf);
		key_buf = NULL;
	}

	if (NULL != adapter)
	{
		sgx_adapter_free(adapter);
		adapter = NULL;
	}

	if (NULL != b64) {
		free(b64);
		b64 = NULL;
	}

	response_headers_free(&headers);
	connector_free(connector);
	token_free(&token);
	return status;
}
