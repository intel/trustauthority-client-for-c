#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <tdx_adapter.h>
#include <token_provider.h>
#include <token_verifier.h>
#include <jwt.h>
#include <log.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define ENV_TRUSTAUTHORITY_API_URL "TRUSTAUTHORITY_API_URL"
#define ENV_TRUSTAUTHORITY_BASE_URL "TRUSTAUTHORITY_BASE_URL"
#define ENV_TRUSTAUTHORITY_API_KEY "TRUSTAUTHORITY_API_KEY"
#define ENV_TRUSTAUTHORITY_POLICY_ID "TRUSTAUTHORITY_POLICY_ID"
#define ENV_RETRY_MAX "RETRY_MAX"
#define ENV_RETRY_WAIT_TIME "RETRY_WAIT_TIME"
#define ENV_REQUEST_ID "REQUEST_ID"
#define ENV_TOKEN_SIG_ALG "TOKEN_SIGNING_ALG"
#define ENV_POLICY_MUST_MATCH "POLICY_MUST_MATCH"


int gen_public_key(int key_bits, unsigned char **key_buffer, int* key_buffer_len) {
    	RSA *rsa = NULL;
    	BIGNUM *bne = NULL;
    	int ret = 0;
    	int key_len = 0;

    	// Initialize OpenSSL
    	OpenSSL_add_all_algorithms();
    	ERR_load_crypto_strings();

    	// Set RSA public exponent
    	bne = BN_new();
    	if (bne == NULL) {
        	ERROR("BN_new failed\n");
        	ret = -1;
        	goto cleanup;
    	}

    	ret = BN_set_word(bne, RSA_F4);
    	if (ret != 1) {
        	ERROR("BN_set_word failed\n");
        	ret = -1;
        	goto cleanup;
    	}

    	// Generate RSA key pair
    	rsa = RSA_new();
    	if (rsa == NULL) {
        	ERROR("RSA_new failed\n");
        	ret = -1;
        	goto cleanup;
    	}
    	
    	ret = RSA_generate_key_ex(rsa, key_bits, bne, NULL);
    	if (ret != 1) {
		ERROR("RSA_generate_key_ex failed\n");
        	ret = -1;
        	goto cleanup;
    	}
	
    	// Extract the modulus and exponent
    	const BIGNUM *n = RSA_get0_n(rsa); // Modulus
    	const BIGNUM *e = RSA_get0_e(rsa); // Public Exponent
    	// Convert the public exponent to a 4-byte array
    	unsigned char *exponent_bytes = calloc(4,  sizeof(unsigned char));
	if (exponent_bytes == NULL) {
        	ERROR("Memory allocation error\n");
        	ret = -1;
        	goto cleanup;
    	}
        if (BN_bn2bin(e, exponent_bytes) == NULL) {
		ERROR("Conversion of exponent failed\n");
		ret = -1;
		goto cleanup;
	}

    	// Convert the modulus to a byte array
    	int n_len = BN_num_bytes(n);
    	unsigned char *modulus_bytes = malloc(n_len);
    	if (modulus_bytes == NULL) {
        	ERROR("Memory allocation error\n");
        	ret = -1;
        	goto cleanup;
    	}
    	if (BN_bn2bin(n, modulus_bytes) == NULL) {
		ERROR("Conversion of Modulus failed\n");
        	ret = -1;
        	goto cleanup;
	}

    	// Combine the exponent and modulus into a single byte array
    	key_len = 4 + n_len;
    	*key_buffer = malloc(key_len);
    	if (*key_buffer == NULL) {
                ERROR("Memory allocation error\n");
                ret = -1;
                goto cleanup;
        }
        memcpy(*key_buffer, exponent_bytes, 4);        // Copy exponent
        memcpy(*key_buffer + 4, modulus_bytes, n_len); // Copy modulus
        *key_buffer_len = key_len;

cleanup:
        if (bne) BN_free(bne);
        if (rsa) RSA_free(rsa);
        if (modulus_bytes) free(modulus_bytes);
        if (exponent_bytes) free(exponent_bytes);
	ERR_free_strings();
        return ret;
}

int main(int argc, char *argv[])
{
	int result;
	trust_authority_connector *connector = NULL;
	evidence_adapter *adapter = NULL;
	token token = {0};
	evidence evidence = {0};
	response_headers headers = {0};
	policies policies = {0};
	char *ta_api_url = getenv(ENV_TRUSTAUTHORITY_API_URL);
	char *ta_base_url = getenv(ENV_TRUSTAUTHORITY_BASE_URL);
	char *ta_key = getenv(ENV_TRUSTAUTHORITY_API_KEY);
	char *policy_id = getenv(ENV_TRUSTAUTHORITY_POLICY_ID);
	char *retry_max_str = getenv(ENV_RETRY_MAX);
	char *retry_wait_time_str = getenv(ENV_RETRY_WAIT_TIME);
	char *request_id = getenv(ENV_REQUEST_ID);
	char *token_signing_alg_str = getenv(ENV_TOKEN_SIG_ALG);
	char *policy_must_match_str = getenv(ENV_POLICY_MUST_MATCH);
	int retry_max, retry_wait_time = 0;
	bool policy_must_match;
	// Store Parsed Token
	jwt_t *parsed_token = NULL;
	collect_token_args token_args = {0};

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

	char *ids[] = {policy_id};
	policies.ids = ids;
	policies.count = 1;

	unsigned char* user_data = NULL;
	int user_data_len;
	result = gen_public_key(3072, &user_data, &user_data_len);
	if( result != 1 ){
		ERROR("ERROR: User Data generation failed\n");
		return 1;
	}
	LOG("Info: connecting to %s\n", ta_api_url);
	result = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Trust Authority Connector: 0x%04x\n", result);
		goto ERROR;
	}

	token_args.policies = &policies;
	token_args.request_id = request_id;
	token_args.token_signing_alg = token_signing_alg_str;
	token_args.policy_must_match = policy_must_match;

#ifdef AZURE_TDX
	result = azure_tdx_adapter_new(&adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create Azure TDX Adapter: 0x%04x\n", result);
		goto ERROR;
	}

	result = tdx_collect_evidence_azure(adapter->ctx, &evidence, NULL, user_data, user_data_len);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to collect evidence from Azure adapter 0x%04x\n", result);
       		goto ERROR;
	}
#else
	result = tdx_adapter_new(&adapter);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to create TDX Adapter: 0x%04x\n", result);
		goto ERROR;
	}

	result = tdx_collect_evidence(adapter->ctx, &evidence, NULL, user_data, user_data_len);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to collect evidence from adapter 0x%04x\n", result);
		goto ERROR;
	}
#endif

	int output_length = ((evidence.evidence_len + 2) / 3) * 4 + 1;
	char *b64 = NULL;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		ERROR("Error: Failed to allocate memory for base64 encoded quote")
		goto ERROR;
	}
	result = base64_encode(evidence.evidence, evidence.evidence_len, b64, output_length, 0);
	if (BASE64_SUCCESS != result)
	{
		ERROR("Error: Failed to base64 encode quote 0x%04x\n", result)
		goto ERROR;
	}
	LOG("Info: quote: %s\n", b64);

	memset(b64, 0, evidence.evidence_len);

#ifdef AZURE_TDX
	output_length = ((evidence.user_data_len + 2) / 3) * 4 + 1;
	result = base64_encode(evidence.user_data, evidence.user_data_len, b64, output_length, 0);
#else
	output_length = ((evidence.runtime_data_len + 2) / 3) * 4 + 1;
	result = base64_encode(evidence.runtime_data, evidence.runtime_data_len, b64, output_length, 0);
#endif

	if (BASE64_SUCCESS != result)
	{
		ERROR("Error: Failed to base64 encode user-data 0x%04x\n", result)
		goto ERROR;
	}
	LOG("Info: user-data: %s\n", b64);

#ifdef AZURE_TDX
	result = collect_token_azure(connector, &headers, &token, &token_args, adapter, user_data, user_data_len);
#else
	result = collect_token(connector, &headers, &token, &token_args, adapter, user_data, user_data_len);
#endif

	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to collect trust authority token: 0x%04x\n", result);
		goto ERROR;
	}

	LOG("Info: Intel Trust Authority Token: %s\n", token.jwt);
	LOG("Info: Headers returned: %s\n", headers.headers);

	result = verify_token(&token, ta_base_url, NULL, &parsed_token, retry_max, retry_wait_time);
	if (STATUS_OK != result)
	{
		ERROR("ERROR: Failed to verify token: 0x%04x\n", result);
		goto ERROR;
	}

	LOG("Info: Successfully verified token\n");
	LOG("Info: Parsed token : ");
	jwt_dump_fp(parsed_token, stdout, 1);

ERROR:

	if (NULL != adapter)
	{
		tdx_adapter_free(adapter);
		adapter = NULL;
	}
	if (NULL != b64)
	{
		free(b64);
		b64 = NULL;
	}
	response_headers_free(&headers);
	connector_free(connector);
	token_free(&token);
	if (NULL != user_data)
	{
		free(user_data);
		user_data = NULL;
	}
	return result;
}
