/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <connector.h>
#include <types.h>
#include <json.h>
#include <appraisal_request.h>
#include <rest.h>
#include <base64.h>
#include <api.h>
#include <log.h>
#include <jwt.h>
#include <regex.h>
#include <curl/curl.h>
#include "mock_server.cpp"
#include <openssl/evp.h>
#include <openssl/pem.h>

// Test case for successful creation of an trust_authority_connector instance
TEST(TANewTest, CreateApiSuccess)
{
	trust_authority_connector *api = nullptr;
	const char *apiKey = "SGVsbG8sIFdvcmxkIW==";
	const char *apiUrl = "https://example.com";

	// Call the trust_authority_connector_new function
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, apiKey, apiUrl,2, 2);

	// Verify the return status is STATUS_OK
	ASSERT_EQ(status, STATUS_OK);

	// Verify that the api pointer is not null
	ASSERT_NE(api, nullptr);

	// Verify that the api_key and api_url have been set correctly
	ASSERT_STREQ(api->api_key, apiKey);
	ASSERT_STREQ(api->api_url, apiUrl);
}

// Test case for null api parameter
TEST(TANewTest, NullApiParameter)
{
	const char *apiKey = "SGVsbG8sIFdvcmxkIW==";
	const char *apiUrl = "https://example.com";

	// Call the trust_authority_connector_new function with null api parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(nullptr, apiKey, apiUrl,0,0);

	// Verify the return status is STATUS_NULL_CONNECTOR
	ASSERT_EQ(status, STATUS_NULL_CONNECTOR);
}

// Test case for null api_key parameter
TEST(TANewTest, NullApiKeyParameter)
{
	trust_authority_connector *api = nullptr;
	const char *apiUrl = "https://example.com";

	// Call the trust_authority_connector_new function with null api_key parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, nullptr, apiUrl,0,0);

	// Verify the return status is STATUS_NULL_API_KEY 
	ASSERT_EQ(status, STATUS_NULL_API_KEY);
}

// Test case for null api_url parameter
TEST(TANewTest, NullClusterUrlParameter)
{
	trust_authority_connector *api = nullptr;
	const char *apiKey = "SGVsbG8sIFdvcmxkIW==";

	// Call the trust_authority_connector_new function with null api_url parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, apiKey, nullptr,0,0);

	// Verify the return status is STATUS_NULL_API_URL
	ASSERT_EQ(status, STATUS_NULL_API_URL);
}

// Test case for invalid api_key parameter
TEST(TANewTest, InvalidLongApiKeyParameter)
{
	trust_authority_connector *api = nullptr;
	const char *apiKey =
		"djE6OThkMzc2M2ItODg4OS00ZmVmLTgzOTItMTJlZGU3MTM0OTRmOmFhYWFhYWFhYWFhYWFhYWFhYWRkZGRkZGRkZGRkRWVyZXJlcmRkZGRkMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDEyMjIyMjIyMjIyMjIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDkzOWtrSGVsbG8sIFdvcmxkIW==_that_is_too_long";
	const char *apiUrl = "https://example.com";

	// Call the trust_authority_connector_new function with an invalid api_key parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, apiKey, apiUrl,0,0);

	// Verify the return status is TRUST_AUTHORITY_STATUS_INVALID_API_KEY
	ASSERT_EQ(status, STATUS_INVALID_API_KEY);
}

// Test case for invalid api_key parameter
TEST(c, InvalidEncodingApiKeyParameter)
{
	trust_authority_connector *api = nullptr;
	const char *apiKey = "my_api_key";
	const char *apiUrl = "https://example.com";

	// Call the trust_authority_connector_new function with an invalid api_key parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, apiKey, apiUrl,0,0);

	// Verify the return status is STATUS_INVALID_API_KEY
	ASSERT_EQ(status, STATUS_INVALID_API_KEY);
}

// Test case for invalid api_url parameter
TEST(TANewTest, InvalidClusterUrlParameter)
{
	trust_authority_connector *api = nullptr;
	const char *apiKey = "SGVsbG8sIFdvcmxkIW==";
	const char *apiUrl =
		"http://example.com/with/a/very/long/path/that/exceeds/the/maximum/allowed/length/************************8";

	// Call the trust_authority_connector_new function with an invalid api_url parameter
	TRUST_AUTHORITY_STATUS status = trust_authority_connector_new(&api, apiKey, apiUrl,0,0);

	// Verify the return status is STATUS_INVALID_API_URL
	ASSERT_EQ(status, STATUS_INVALID_API_URL);
}

// Test case for get_nonce function
TEST(ApiTest, GetNonce)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"signature\":\"SGVsbG8sIFdvcmxkIW==\"}");
	mockServer.start();

	// Prepare the API and nonce structures
	trust_authority_connector api = { 0 };
	nonce nonce = { 0 };
	response_headers headers = { 0 };
	api.retries = (retry_config *)calloc(1, sizeof(retry_config));

	if (NULL == api.retries)
	{
		ERROR("Error: In memory allocation for retries\n");
	}
	api.retries->retry_max = DEFAULT_RETRY_MAX;
	api.retries->retry_wait_time = DEFAULT_RETRY_WAIT_TIME;

	// Set the values of the `api` structure
	strncpy(api.api_url, "http://localhost:8080", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	// Perform the API call and retrieve the nonce
	TRUST_AUTHORITY_STATUS result = get_nonce(&api, &nonce, "1234", &headers);

	// Assert the result is successful
	ASSERT_EQ(result, STATUS_OK);
	// Assert that the nonce fields contain expected values
	ASSERT_NE(nonce.val, nullptr);	// Nonce should not be null
	ASSERT_GT(nonce.val_len, 0);	// Nonce length should be greater than 0
	ASSERT_NE(nonce.iat, nullptr);	// Nonce iat should not be null
	ASSERT_GT(nonce.iat_len, 0);	// Nonce iat length should be greater than 0
	ASSERT_NE(nonce.signature, nullptr);	// Signature should not be null
	ASSERT_GT(nonce.signature_len, 0);	// Signature length should be greater than 0

	free(api.retries);
	mockServer.stop();
}

TEST(URLTest, ValidURL)
{
	const char *url = "https://test.com";
	int result = is_valid_url(url);

	// Result should equal to 0 if the url is valid
	ASSERT_EQ(result, 0);
}

TEST(URLTest, InvalidURL)
{
	const char *url = "123456";
	int result = is_valid_url(url);

	// Result should equal to 1 if the url is invalid
	ASSERT_EQ(result, 1);
}

TEST(UUIDTest, ValidUUID)
{
	const char *uuid = "2f546239-b43f-4196-98d2-e8d52733dbbc";
	int result = is_valid_uuid(uuid);

	// Result should equal to 0 if the uuid is valid
	ASSERT_EQ(result, 0);
}

TEST(UUIDTest, InvalidUUID)
{
	const char *uuid = "00000000000000000000000000000000";
	int result = is_valid_uuid(uuid);
	// Result should not equal to 0 if the uuid is invalid
	ASSERT_NE(result, 0);

	const char *empty_str = "";
	char *empty_uuid = (char *) calloc(1, sizeof(char));

	if (NULL == empty_uuid)
	{
		ERROR("Error: In memory allocation for empty_uuid\n");
	}

	memcpy(empty_uuid, empty_str, 1);

	result = is_valid_uuid(empty_uuid);

	// Result should not equal to 0 if the uuid is invalid
	ASSERT_NE(result, 0);
	free(empty_uuid);
	empty_uuid = NULL;
}

// Test case for negative scenario - api is null
TEST(TokenTest, ApiNullError)
{
	TRUST_AUTHORITY_STATUS result = get_token(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	// Should throw error - api is null
	ASSERT_EQ(result, STATUS_NULL_CONNECTOR);
}

// Test case for negative scenario - token is null
TEST(TokenTest, TokenNullError)
{
	trust_authority_connector api;
	TRUST_AUTHORITY_STATUS result = get_token(&api, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	// Should throw error - token is null
	ASSERT_EQ(result, STATUS_NULL_TOKEN);
}

// Test case for negative scenario - evidence is null
TEST(TokenTest, EvidenceNullError)
{
	trust_authority_connector api;
	token token;
	policies policy;
	TRUST_AUTHORITY_STATUS result = get_token(&api, NULL, &token, &policy, NULL, NULL, NULL, NULL);

	// Should throw error - Evidence is null
	ASSERT_EQ(result, STATUS_NULL_EVIDENCE);
}

// Test case for negative scenario - evidence data is null
TEST(TokenTest, EvidenceDataNullError)
{
	trust_authority_connector api;
	token token;
	policies policy;
	evidence *ta_evidence;
	evidence evidenceObj;
	ta_evidence = &evidenceObj;
	ta_evidence->evidence = NULL;
	TRUST_AUTHORITY_STATUS result = get_token(&api, NULL, &token, &policy, ta_evidence, NULL, NULL, NULL);

	// Should throw error - Evidence data is null
	ASSERT_EQ(result, STATUS_INVALID_PARAMETER);
}

// Test case for negative scenario - evidence data exceeds maximum length
TEST(TokenTest, EvidenceDataError)
{
	trust_authority_connector api;
	token token;
	policies policy;
	evidence *ta_evidence;
	evidence evidenceObj;
	ta_evidence = &evidenceObj;
	ta_evidence->type = 1;
	ta_evidence->evidence_len = MAX_EVIDENCE_LEN + 1;	// Exceed the maximum length
	ta_evidence->evidence = new uint8_t[ta_evidence->evidence_len];
	strncpy((char *) ta_evidence->evidence, "data1", ta_evidence->evidence_len);
	TRUST_AUTHORITY_STATUS result = get_token(&api, NULL, &token, &policy, ta_evidence, NULL, NULL, NULL);

	// Should throw error - Evidence data exceeds maximum length
	ASSERT_EQ(result, STATUS_INVALID_PARAMETER);
}

// Test case for negative scenario - nonce is null
TEST(TokenTest, NonceNullError)
{
	trust_authority_connector api;
	token token;
	policies policy;
	evidence *ta_evidence;
	evidence evidenceObj;
	ta_evidence = &evidenceObj;
	ta_evidence->type = 1;
	ta_evidence->evidence_len = MAX_EVIDENCE_LEN;
	ta_evidence->evidence = new uint8_t[ta_evidence->evidence_len];
	strncpy((char *) ta_evidence->evidence, "data1", ta_evidence->evidence_len);
	TRUST_AUTHORITY_STATUS result = get_token(&api, NULL, &token, &policy, ta_evidence, NULL, NULL, NULL);

	// Should throw error - nonce is null
	ASSERT_EQ(result, STATUS_NULL_NONCE);
}

// Test case for successful retrieval of token
TEST(TokenTest, RetrieveTokenSuccess)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEyMyIsImprdSI6Imh0dHBzOlxcbG9jYWxob3N0OjgwODAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cCOaUSoglcRlEiqoKIxV0bC8PptNuedV_EaXD2BDCng\"}");
	mockServer.start();
	trust_authority_connector *api = nullptr;
	const char *apiKey = "SGVsbG8sIFdvcmxkIW==";
	const char *apiUrl = "https://localhost:8080";
	token *ta_token = nullptr;
	response_headers resp_headers = { 0 };
	policies *ta_policies = nullptr;
	evidence *ta_evidence = nullptr;
	nonce *ta_nonce = nullptr;
	// Create an trust_authority_connector instance
	TRUST_AUTHORITY_STATUS createStatus = trust_authority_connector_new(&api, apiKey, apiUrl,2,2);

	ASSERT_EQ(createStatus, STATUS_OK);
	ASSERT_NE(api, nullptr);
	strncpy(api->api_url, "http://localhost:8080", API_URL_MAX_LEN);	

	// Set up the necessary structures and data for the test
	token tokenObj = { 0 };
	policies policiesObj = { 0 };
	evidence evidenceObj = { 0 };
	nonce nonceObj = { 0 };
	char attestation_url[API_KEY_MAX_LEN + 1] = { 0 };

	ta_token = &tokenObj;
	ta_policies = &policiesObj;
	ta_evidence = &evidenceObj;
	ta_nonce = &nonceObj;

	// Set up the necessary data for the structures
	ta_policies->count = 1;
	ta_policies->ids = new char *[1];
	ta_policies->ids[0] = new char[10];
	strncpy(ta_policies->ids[0], "policy1", 8);

	ta_evidence->type = 1;
	ta_evidence->evidence_len = 5;
	ta_evidence->evidence = new uint8_t[10];
	strncpy((char *) ta_evidence->evidence, "data1", 6);

	ta_evidence->user_data_len = 5;
	ta_evidence->user_data = new uint8_t[10];
	strncpy((char *) ta_evidence->user_data, "data1", 6);

	ta_nonce->val_len = 6;
	ta_nonce->val = new uint8_t[10];
	strncpy((char *) ta_nonce->val, "nonce1", 7);
	ta_nonce->iat_len = 5;
	ta_nonce->iat = new uint8_t[10];
	strncpy((char *) ta_nonce->iat, "iatda", 6);
	ta_nonce->signature_len = 5;
	ta_nonce->signature = new uint8_t[10];
	strncpy((char *) ta_nonce->signature, "sign1", 6);

	strncat(attestation_url, "/appraisal/v1/attest", API_URL_MAX_LEN);

	// Call the get_token function
	TRUST_AUTHORITY_STATUS getTokenStatus = get_token(api, &resp_headers, ta_token, ta_policies, ta_evidence, ta_nonce, NULL, attestation_url);

	// Verify the return status is STATUS_OK
	ASSERT_EQ(getTokenStatus, STATUS_OK);

	// Clean up allocated memory
	delete[]ta_policies->ids[0];
	delete[]ta_policies->ids;
	delete[]ta_evidence->evidence;
	delete[]ta_nonce->val;
	delete[]ta_nonce->iat;
	delete[]ta_nonce->signature;

	mockServer.stop();
}

TEST(GeneratePubkeyTest, ValidInputs)
{
	const char *exponent = "AQAB";
	const char *modulus =
		"2AvLXW7ZGh+NfTzwzY3U3M5j1tsgW2dxDF5I7aGL3i7J/4u3CZt9ZV6A3N6A6DrQ"
		"MzqIgMRZ6dLyz4Ud7zqic47B6P1cO9R1jE4FDYaMikCh5/viKY8KjHFSZMSUGWsE"
		"Nf1Y7m3vxf2Mj7D7/hWiG53An0GrMz3GkRtlQzV6JHs=";
	EVP_PKEY *pubkey = nullptr;
	TRUST_AUTHORITY_STATUS status = generate_pubkey_from_exponent_and_modulus(exponent, modulus, &pubkey);

	EXPECT_EQ(status, STATUS_OK);
	EXPECT_NE(pubkey, nullptr);

	EVP_PKEY_free(pubkey);
}

TEST(GeneratePubkeyTest, InvalidEncoding)
{
	const char *exponent = "invalid";	// Invalid base64 encoding
	const char *modulus =
		"2AvLXW7ZGh+NfTzwzY3U3M5j1tsgW2dxDF5I7aGL3i7J/4u3CZt9ZV6A3N6A6DrQ"
		"MzqIgMRZ6dLyz4Ud7zqic47B6P1cO9R1jE4FDYaMikCh5/viKY8KjHFSZMSUGWsE"
		"Nf1Y7m3vxf2Mj7D7/hWiG53An0GrMz3GkRtlQzV6JHs=";
	EVP_PKEY *pubkey = nullptr;
	TRUST_AUTHORITY_STATUS status = generate_pubkey_from_exponent_and_modulus(exponent, modulus, &pubkey);

	EXPECT_EQ(status, STATUS_GENERATE_PUBKEY_ERROR);
	EXPECT_EQ(pubkey, nullptr);
}

// Positive test case
TEST(FormatPubKeyTest, FormatPubKey_Success)
{
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);
	RSA_generate_key_ex(rsa, 2048, e, NULL);

	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	const char *formatted_pub_key = nullptr;
	TRUST_AUTHORITY_STATUS status = format_pubkey(pkey, &formatted_pub_key);

	ASSERT_EQ(STATUS_OK, status);
	ASSERT_NE(nullptr, formatted_pub_key);

	EVP_PKEY_free(pkey);
	OPENSSL_free((void *) formatted_pub_key);
}

// Test case for failure to retrieve token signing certificate
TEST(GetJwksTest, RetrieveCertificateFailure)
{
	const char *certUrl = "http://localhost:8080/token_signing_cert1";
	char *pemCertificate = nullptr;

	// Call the get_token_signing_certificate function
	TRUST_AUTHORITY_STATUS getCertificateStatus = get_token_signing_certificate(certUrl, &pemCertificate, 0,0);

	// Verify the return status is STATUS_GET_SIGNING_CERT_ERROR
	ASSERT_EQ(getCertificateStatus, STATUS_GET_SIGNING_CERT_ERROR);

	// Verify that the pem_certificate is null
	ASSERT_EQ(pemCertificate, nullptr);
}

// Test case for success scenario when certificate is retrieved.
TEST(GetJwksTest, RetrieveCertificateSuccess)
{
	// Start the mock server
	MockServer mockServer("Mock Cert data");
	mockServer.start();

	const char *certUrl = "http://localhost:8080/token_signing_cert";
	char *pemCertificate = nullptr;
	retry_config retries = { .retry_wait_time=1, .retry_max=1 };

	// Call the get_token_signing_certificate function
	TRUST_AUTHORITY_STATUS getCertificateStatus = get_token_signing_certificate(certUrl, &pemCertificate, 0,0);

	// Verify the return status is STATUS_OK
	ASSERT_EQ(getCertificateStatus, STATUS_OK);

	// Verify that the pem_certificate has been assigned correctly
	ASSERT_STREQ(pemCertificate, "Mock Cert data");
	mockServer.stop();
}

// Negative test case - KID field not found
TEST(TokenTest, ParseTokenHeaderKidFieldNotFound)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.";
	char *jwtmissingKid = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == jwtmissingKid)
	{
		ERROR("Error: In memory allocation for jwtmissingKid\n");
	}

	memcpy(jwtmissingKid, samplejwt, 38);
	ta_token->jwt = jwtmissingKid;

	TRUST_AUTHORITY_STATUS status =
		parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_KID_NULL_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(jwtmissingKid);
	jwtmissingKid = NULL;
}

// Fail in splitting header
TEST(TokenTest, ParseTokenHeaderSplitFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9";
	char *samplejwt = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 38);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_INVALID_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

// Fail in base64 decoding of header
TEST(TokenTest, ParseTokenHeaderDecodeFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9123.";
	char *samplejwt = (char *) calloc(1, 42 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 41);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_DECODE_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

// Fail in json load
TEST(TokenTest, ParseTokenHeaderJsonLoadFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVH0=.";
	char *samplejwt = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 38);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_DECODE_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

// Test case for a valid modulus and exponent
TEST(GenPubKey, ValidModulusExponent)
{
	const char *n =
		"3bmGZLQSl3-wvGZVrZeI-HGz0XjB6F1lcwyxGRNl4GN3c7qHJyK5EiTqBNHKCQ76njmbERvIph8NlrH4G5l8tWUbB5z3vQYBkegc-fK0q7-QAZMJ9GglxjbppeIHpvYlk5G04CNedzyxA4SG2KNPdELgXYZDOVKtmd2jSSVys1P81H7olm1TS_3jTZP9PScY0t0fOibzzOFK7pdpfz6yjMt2FMLwMtLYNcZ2QaBRqFntNZ5biDiSsk60M5f_DwwAAKnDMZ5pT0qDeFMo8JQfhGMhr8a46oNXXbRmLXGUEytbiesQPVaTMpDkWqyxq_pOFhn2Er99i698YS6LNuZpeQ==";
	const char *e = "AQAB";
	EVP_PKEY *pubkey = (EVP_PKEY *) malloc(3072);

	// Call the get_token_signing_certificate function
	TRUST_AUTHORITY_STATUS keyGenStatus = generate_pubkey_from_exponent_and_modulus(n, e, &pubkey);

	// Verify the return status is STATUS_OK
	ASSERT_EQ(keyGenStatus, STATUS_OK);

	free(pubkey);
	pubkey = NULL;
}

// Test case to free trust_authority_connector - Success case
TEST(ApiFree, SuccessCase)
{
	trust_authority_connector *connector=NULL;
	connector = (trust_authority_connector*) calloc(1, sizeof(trust_authority_connector));
	TRUST_AUTHORITY_STATUS result = connector_free(connector);

	// Result should be STATUS_OK
	ASSERT_EQ(result, STATUS_OK);
}

// Test case to free nonce - Success case
TEST(NonceFree, SuccessCase)
{
	// Create a sample nonce
	nonce *ta_nonce = (nonce *) malloc(sizeof(nonce));
	ta_nonce->val = (uint8_t *) malloc(10);
	ta_nonce->iat = (uint8_t *) malloc(10);
	ta_nonce->signature = (uint8_t *) malloc(20);

	// Call the function under test
	TRUST_AUTHORITY_STATUS result = nonce_free(ta_nonce);
	free(ta_nonce);

	// Verify the result - status_ok
	ASSERT_EQ(result, STATUS_OK);
}

// Test case to free token - Success case
TEST(TokenFree, SuccessCase)
{
	token *ta_token = NULL;
	ta_token = (token *) malloc(sizeof(token));
	ta_token->jwt = (char *) malloc(10);
	TRUST_AUTHORITY_STATUS result = token_free(ta_token);
	free(ta_token);

	// Result should be status_ok
	ASSERT_EQ(result, STATUS_OK);
}

// Test case to free evidence - Success case
TEST(EvidenceFree, SuccessCase)
{
	evidence *ta_evidence;
	ta_evidence = (evidence *) malloc(sizeof(evidence));
	ta_evidence->evidence = (uint8_t *) malloc(10);
	ta_evidence->user_data = (uint8_t *) malloc(20);
	ta_evidence->event_log = (uint8_t *) malloc(20);

	TRUST_AUTHORITY_STATUS result = evidence_free(ta_evidence);

	// Result should be status_ok
	ASSERT_EQ(result, STATUS_OK);
}
