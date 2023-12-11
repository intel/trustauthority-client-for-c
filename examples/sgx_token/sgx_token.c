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
#define ENCLAVE_PATH "enclave.signed.so"

int main(int argc, char *argv[])
{
	int status = 0;
	trust_authority_connector *connector = NULL;
	token token = {0};
	response_headers headers = {0};
	evidence_adapter *adapter = NULL;
	policies policies = {0};
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_id = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *request_id = getenv(ENV_REQUEST_ID);
	int retry_max, retry_wait_time = 0;
	// Create enclave and get id
	sgx_enclave_id_t eid = 0;
	// Enclave public key
	uint32_t key_size;
	uint8_t *key_buf = NULL;
	// Store Parsed Token
	jwt_t *parsed_token = NULL;

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

	if (NULL == policy_id || !strlen(policy_id))
	{
		ERROR("ERROR: Environment variable is required %s\n", ENV_TRUSTAUTHORITY_POLICY_ID);
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

	if (0 != is_valid_uuid(policy_id))
	{
		ERROR("ERROR: Invalid UUID format");
		return 1;
	}

	if (0 != is_valid_url(ta_base_url))
	{
		ERROR("ERROR: Invalid TRUSTAUTHORITY_BASE_URL format\n");
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

	status = collect_token(connector, &headers, &token, &policies, request_id, adapter, key_buf, key_size);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", status);
		goto ERROR;
	}

	LOG("Info: trust authority token: %s\n", token.jwt);

	status = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != status)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", status);
		goto ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: \nParsed token : \n");
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

	connector_free(connector);
	token_free(&token);
	return status;
}
