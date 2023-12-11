#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <tdx_adapter.h>
#include <token_provider.h>
#include <token_verifier.h>
#include <jwt.h>
#include <log.h>

#define ENV_TRUSTAUTHORITY_API_URL "TRUSTAUTHORITY_API_URL"
#define ENV_TRUSTAUTHORITY_BASE_URL "TRUSTAUTHORITY_BASE_URL"
#define ENV_TRUSTAUTHORITY_API_KEY "TRUSTAUTHORITY_API_KEY"
#define ENV_TRUSTAUTHORITY_POLICY_ID "TRUSTAUTHORITY_POLICY_ID"
#define ENV_RETRY_MAX "RETRY_MAX"
#define ENV_RETRY_WAIT_TIME "RETRY_WAIT_TIME"
#define ENV_REQUEST_ID "REQUEST_ID"

// env TRUSTAUTHORITY_BASE_URL=https://{{TRUSTAUTHORITY_IP}} TRUSTAUTHORITY_API_KEY={{API_KEY}} TRUSTAUTHORITY_POLICY_ID={{POLICY_ID}} no_proxy={{TRUSTAUTHORITY_IP}} tdx_token

int main(int argc, char *argv[])
{
	int result;
	trust_authority_connector *connector = NULL;
	evidence_adapter *adapter = NULL;
	token token = {0};
	response_headers headers = {0};
	policies policies = {0};
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_id = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *request_id = getenv(ENV_REQUEST_ID);
	int retry_max, retry_wait_time = 0;
	// Store Parsed Token
	jwt_t *parsed_token = NULL;

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

	if (NULL == policy_id || !strlen(policy_id))
	{
		ERROR("ERROR: %s - environment variable is required\n", ENV_TRUSTAUTHORITY_POLICY_ID);
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

	char *user_data = "data generated inside tee";
	int user_data_len = strnlen(user_data, MAX_USER_DATA_LEN);

	LOG("Info: connecting to %s\n", ta_api_url);

	result = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Trust Authority Connector: 0x%04x\n", result);
		goto ERROR;
	}

	result = tdx_adapter_new(&adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create TDX Adapter: 0x%04x\n", result);
		goto ERROR;
	}

	LOG("Info: Collecting token... \n");

	result = collect_token(connector, &headers, &token, &policies, request_id, adapter, user_data, user_data_len);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", result);
		goto ERROR;
	}

	LOG("Info: Intel Trust Authority Token: %s\n", token.jwt);

	result = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", result);
		goto ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: \nParsed token : \n");
	jwt_dump_fp(parsed_token, stdout, 1);

ERROR:

	if (NULL != adapter)
	{
		tdx_adapter_free(adapter);
		adapter = NULL;
	}

	connector_free(connector);
	token_free(&token);

	return result;
}
