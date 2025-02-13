#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <sgx_adapter.h>
#include <token_verifier.h>
#include <evidence_builder.h>
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
	nonce nonce = {0};
	token token = {0};
	json_t *evidence = NULL;
	response_headers headers = {0};
	evidence_adapter *adapter = NULL;
	evidence_builder *builder = NULL;
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_ids = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
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
	builder_opts opts = {0};
	get_nonce_args nonce_args = {0};

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

	if (STATUS_OK != is_valid_token_sigining_alg(token_sign_alg_str))
	{
		ERROR("ERROR: Unsupported Token Signing Algorithm, supported algorithms are RS256/PS384\n");
		return 1;
	}

	if (STATUS_OK != validate_and_get_policy_must_match(policy_must_match_str, &policy_must_match))
	{
		ERROR("ERROR: Unsupported Policy Match Value, supported values are true/false\n");
		return 1;
	}

	if (0 != validate_request_id(request_id))
	{
		ERROR("ERROR: Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \\");
		return 1;
	}

	LOG("Info: Connecting to %s\n", ta_api_url);
	status = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create Trust Authority Connector: 0x%04x\n", status);
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

	evidence = json_object();
	status = sgx_get_evidence(adapter->ctx, evidence, NULL, key_buf, key_size);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to collect evidence from adapter 0x%04x\n", status);
		goto ERROR;
	}

	// Serialize the JSON object to a string and print it
	char *json_string = json_dumps(evidence, JSON_INDENT(4));
	if(NULL == json_string)
	{
		ERROR("ERROR: Failed to serialize evidence to json string\n");
		goto ERROR;
	}
	LOG("Info: Evidence: %s\n", json_string);
	json_decref(evidence);
	free(json_string);

	nonce_args.request_id = request_id;
	status = get_nonce(connector, &nonce, &nonce_args, &headers);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to get Trust Authority nonce 0x%04x\n", status);
		goto ERROR;
	}

	opts.nonce = &nonce;
	opts.user_data = key_buf;
	opts.user_data_len = key_size;
	opts.policy_ids = policy_ids;
	opts.policy_must_match = policy_must_match;
	opts.token_signing_alg = token_sign_alg_str;
	status = evidence_builder_new(&builder, &opts);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to create evidence builder: 0x%04x\n", status);
		goto ERROR;
	}

	status = evidence_builder_add_adapter(builder, adapter);
	if(STATUS_OK != status)
	{
		ERROR("ERROR: Failed to add adapter to builder: 0x%04x\n", status);
		goto ERROR;
	}

	evidence = json_object();
	status = evidence_builder_get_evidence(builder, evidence);
	if(STATUS_OK != status)
	{
		ERROR("ERROR: Failed to get evidence from builder: 0x%04x\n", status);
		goto ERROR;
	}

	status = attest_evidence(connector, &headers, &token, evidence, request_id, "");
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", status);
		goto ERROR;
	}
	LOG("Info: Trust Authority Token: %s\n", token.jwt);
	LOG("Info: Headers returned: %s\n",headers.headers);

	status = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", status);
		goto ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: Parsed token: ");
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
	if (NULL != evidence)
	{
		json_decref(evidence);
		evidence = NULL;
	}

	response_headers_free(&headers);
	evidence_builder_free(builder);
	sgx_adapter_free(adapter);
	connector_free(connector);
	jwt_free(parsed_token);
	token_free(&token);
	nonce_free(&nonce);
	return status;
}
