/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include <string.h>
#include <types.h>
#include <json.h>
#include <log.h>
#include <base64.h>
#include <appraisal_request.h>
#include <log.h>
#include <gtest/gtest.h>

extern "C"
{
	TRUST_AUTHORITY_STATUS get_jansson_nonce(nonce *nonce, json_t **jansson_nonce);
}

// Test case for get_jansson_nonce
TEST(GetJanssonNonceTest, ValidNonce)
{
	// Create a valid nonce
	nonce nonce;
	nonce.val_len = 6;
	nonce.val = new uint8_t[10];
	strncpy((char *)nonce.val, "nonce1", 7);
	nonce.iat_len = 5;
	nonce.iat = new uint8_t[10];
	strncpy((char *)nonce.iat, "iatda", 6);
	nonce.signature_len = 5;
	nonce.signature = new uint8_t[10];
	strncpy((char *)nonce.signature, "sign1", 6);

	// Declare the jansson_nonce variable
	json_t *jansson_nonce = nullptr;

	// Call the function being tested
	TRUST_AUTHORITY_STATUS result = get_jansson_nonce(&nonce, &jansson_nonce);

	// Check the result
	ASSERT_EQ(STATUS_OK, result);
	ASSERT_TRUE(jansson_nonce != nullptr);
}

TEST(GetJanssonNonceTest, NullNonce)
{
	// Declare the nonce and jansson_nonce variables
	nonce *nonce = nullptr;
	json_t *jansson_nonce = nullptr;

	// Call the function being tested
	TRUST_AUTHORITY_STATUS result = get_jansson_nonce(nonce, &jansson_nonce);

	// Check the result
	ASSERT_EQ(STATUS_NULL_NONCE, result);
	ASSERT_TRUE(jansson_nonce == nullptr);
}

TEST(GetJanssonNonceTest, NullJanssonNonce)
{
	// Create a valid nonce
	nonce nonce;
	nonce.val_len = 6;
	nonce.val = new uint8_t[10];
	strncpy((char *)nonce.val, "nonce1", 7);
	nonce.iat_len = 5;
	nonce.iat = new uint8_t[10];
	strncpy((char *)nonce.iat, "iatda", 6);
	nonce.signature_len = 5;
	nonce.signature = new uint8_t[10];
	strncpy((char *)nonce.signature, "sign1", 6);

	// Call the function being tested
	TRUST_AUTHORITY_STATUS result = get_jansson_nonce(&nonce, nullptr);

	// Check the result
	ASSERT_EQ(STATUS_INVALID_PARAMETER, result);
}

// Test case for a valid JSON input
TEST(JsonUnmarshalNonceTest, ValidJsonInput)
{

	const char *json = R"({
        "val": "SGVsbG8sIFdvcmxkIW==",
        "iat": "SGVsbG8sIFdvcmxkIW==",
        "signature": "SGVsbG8sIFdvcmxkIW=="
    })";

	nonce nonce = {0};
	TRUST_AUTHORITY_STATUS status = json_unmarshal_nonce(&nonce, json);

	// Assert that the function returns STATUS_OK
	EXPECT_EQ(status, STATUS_OK);

	// Assert that the nonce and signature fields are correctly populated
	EXPECT_TRUE(nonce.val != nullptr);
	EXPECT_GT(nonce.val_len, 0);
	EXPECT_TRUE(nonce.iat != nullptr);
	EXPECT_GT(nonce.iat_len, 0);
	EXPECT_TRUE(nonce.signature != nullptr);
	EXPECT_GT(nonce.signature_len, 0);
}

// Test case for an invalid JSON input
TEST(JsonUnmarshalNonceTest, InvalidJsonInput)
{
	const char *json = "invalid_json";

	nonce nonce;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_nonce(&nonce, json);

	// Assert that the function returns STATUS_JSON_NONCE_PARSING_ERROR
	EXPECT_EQ(status, STATUS_JSON_NONCE_PARSING_ERROR);
}

// Test case for JSON input with missing fields
TEST(JsonUnmarshalNonceTest, MissingFields)
{
	const char *json = R"({
        "val": "BASE64_ENCODED_NONCE_VALUE"
        // "signature" field is missing
    })";

	nonce nonce;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_nonce(&nonce, json);

	// Assert that the function returns STATUS_JSON_NONCE_PARSING_ERROR
	EXPECT_EQ(status, STATUS_JSON_NONCE_PARSING_ERROR);
}

// Test case for base64 decoding error
TEST(JsonUnmarshalNonceTest, Base64DecodingError)
{
	const char *json = R"({
        "val": ,
        "iat": "BASE64_ENCODED_SIGNATURE_VALUE",
        "signature": "BASE64_ENCODED_SIGNATURE_VALUE"
    })";

	nonce nonce;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_nonce(&nonce, json);

	// Assert that the function returns STATUS_JSON_NONCE_PARSING_ERROR
	EXPECT_EQ(status, STATUS_JSON_NONCE_PARSING_ERROR);
}

// Positive test case
TEST(JsonMarshalNonceTest, ValidParameters)
{
	nonce nonce;
	char *json = nullptr;

	// Initialize nonce struct with valid data
	nonce.val_len = 6;
	nonce.val = new uint8_t[10];
	strncpy((char *)nonce.val, "nonce1", 7);
	nonce.iat_len = 5;
	nonce.iat = new uint8_t[10];
	strncpy((char *)nonce.iat, "iatda", 6);
	nonce.signature_len = 5;
	nonce.signature = new uint8_t[10];
	strncpy((char *)nonce.signature, "sign1", 6);

	TRUST_AUTHORITY_STATUS status = json_marshal_nonce(&nonce, &json);

	// Assert
	EXPECT_EQ(STATUS_OK, status);
	EXPECT_TRUE(json != nullptr);
}

// Negative test case - nonce is NULL
TEST(JsonMarshalNonceTest, NullNonce)
{
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_nonce(nullptr, &json);

	// Assert
	EXPECT_EQ(STATUS_NULL_NONCE, status);
}

// Negative test case - json is NULL
TEST(JsonMarshalNonceTest, NullJson)
{
	nonce nonce;
	// Initialize nonce struct with valid data
	nonce.val_len = 6;
	nonce.val = new uint8_t[10];
	strncpy((char *)nonce.val, "nonce1", 7);
	nonce.iat_len = 5;
	nonce.iat = new uint8_t[10];
	strncpy((char *)nonce.iat, "iatda", 6);
	nonce.signature_len = 5;
	nonce.signature = new uint8_t[10];
	strncpy((char *)nonce.signature, "sign1", 6);

	TRUST_AUTHORITY_STATUS status = json_marshal_nonce(&nonce, NULL);
	// Assert
	EXPECT_EQ(STATUS_INVALID_PARAMETER, status);
}

// Positive test case - json_unmarshal_evidence
TEST(JsonUnmarshalEvidenceTest, ValidParameters)
{
	evidence evidence = {0};
	const char *json = "{\"type\":\"12\",\"evidence\":\"SGVsbG8sIFdvcmxkIW==\",\"evidence_len\":2,\"user_data\":\"SGVsbG8sIFdvcmxkIW==\",\"user_data_len\":2,\"event_log\":\"SGVsbG8sIFdvcmxkIW==\",\"event_log_len\":2}";

	TRUST_AUTHORITY_STATUS status = json_unmarshal_evidence(&evidence, json);
	// Assert
	EXPECT_EQ(STATUS_OK, status);
	EXPECT_EQ(12, evidence.type);
}

// Negative test case - json_unmarshal_evidence with invalid JSON
TEST(JsonUnmarshalEvidenceTest, InvalidJson)
{
	evidence evidence;
	const char *json = "invalid_json";
	TRUST_AUTHORITY_STATUS status = json_unmarshal_evidence(&evidence, json);
	// Assert
	EXPECT_EQ(STATUS_JSON_ERROR, status);
}

// Positive test case - json_marshal_evidence
TEST(JsonMarshalEvidenceTest, ValidParameters)
{
	evidence evidence;
	char *json = nullptr;
	// Initialize evidence with valid data
	evidence.type = 1;
	evidence.evidence_len = 5;
	evidence.evidence = new uint8_t[10];
	strncpy((char *)evidence.evidence, "data1", 6);

	evidence.user_data_len = 5;
	evidence.user_data = new uint8_t[10];
	strncpy((char *)evidence.user_data, "data1", 6);

	TRUST_AUTHORITY_STATUS status = json_marshal_evidence(&evidence, &json);

	// Assert
	EXPECT_EQ(STATUS_OK, status);
	EXPECT_TRUE(json != nullptr);
}

// Negative test case - json_marshal_evidence with NULL evidence
TEST(JsonMarshalEvidenceTest, NullEvidence)
{
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_evidence(nullptr, &json);

	// Assert
	EXPECT_EQ(STATUS_NULL_EVIDENCE, status);
}

TEST(JsonUnmarshalTAJwksTest, EmptyCertParameterReturnsInvalidParameter)
{
	const char *json = "{}";
	TRUST_AUTHORITY_STATUS status = json_unmarshal_token_signing_cert(nullptr, json);

	// Assert
	EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

TEST(JsonUnmarshalTAJwksTest, EmptyKeyError)
{
	jwks *cert = nullptr;
	const char *json = "{}";
	TRUST_AUTHORITY_STATUS status = json_unmarshal_token_signing_cert(&cert, json);

	// Assert
	EXPECT_EQ(status, STATUS_JSON_SIGN_CERT_PARSING_KEYS_FIELD_NOT_FOUND_ERROR);
	EXPECT_EQ(cert, nullptr);
}

TEST(JsonUnmarshalTAJwksTest, EmptyJsonDataReturnsInvalidParameter)
{
	jwks *cert = nullptr;
	const char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_token_signing_cert(&cert, json);

	// Assert
	EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
	EXPECT_EQ(cert, nullptr);
}

TEST(JsonUnmarshalTAJwksTest, ValidJsonReturnsOk)
{
	// Arrange
	jwks *cert = nullptr;
	const char *json = R"({
        "keys": [
            {
                "kty": "RSA",
                "kid": "123",
                "n": "abc",
                "e": "def",
                "alg": "RS256",
                "x5c": ["cert1", "cert2"]
            }
        ]
    })";

	TRUST_AUTHORITY_STATUS status = json_unmarshal_token_signing_cert(&cert, json);

	// Assert
	EXPECT_EQ(status, STATUS_OK);
	ASSERT_NE(cert, nullptr);
	EXPECT_STREQ(cert[0].keytype, "RSA");
	EXPECT_STREQ(cert[0].kid, "123");
	EXPECT_STREQ(cert[0].n, "abc");
	EXPECT_STREQ(cert[0].e, "def");
	EXPECT_STREQ(cert[0].alg, "RS256");
	EXPECT_EQ(cert[0].num_of_x5c, 2);
	EXPECT_STREQ(cert[0].x5c[0], "cert1");
	EXPECT_STREQ(cert[0].x5c[1], "cert2");
}

TEST(JsonUnmarshalAppraisalRequestTest, PositiveTest)
{
	const char *json = "{ \"quote\": \"sample_quote\", "
		"  \"verifier_nonce\": { \"val\": \"sample_nonce\",\"iat\": \"sample_iatda\",\"signature\": \"sample_signature\" }, "
		"  \"runtime_data\": \"sample_user_data\", "
		"  \"policy_ids\": [\"policy1\", \"policy2\"]"
		"}";
	appraisal_request request = {0};
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	ASSERT_EQ(status, STATUS_OK);
}

TEST(JsonUnmarshalAppraisalRequestTest, EmptyJsonTest)
{
	const char *json = nullptr;
	appraisal_request request = {0};
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);
	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);
}

// Test case for empty appraisal request
TEST(JsonUnmarshalAppraisalRequestTest, EmptyAppraisalRequest)
{
	const char *json = "{ \"quote\": \"quote_data\", \"user_data\": \"user_data\", \"policy_ids\": [\"policy1\", \"policy2\"] }";
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(NULL, json);

	EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

// Test case for missing signed_nonce field
TEST(JsonUnmarshalAppraisalRequestTest, MissingSignedNonceField)
{
	const char *json = "{ \"quote\": \"sample_quote\", "
		"  \"verifier_nonce\": { \"iat\": \"sample_iatda\",\"signature\": \"sample_signature\" }, "
		"  \"user_data\": \"userdata\" "
		"}";
	appraisal_request request;

	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_JSON_NONCE_PARSING_ERROR);
}

// Test case for empty JSON data
TEST(JsonUnmarshalAppraisalRequestTest, EmptyJsonData)
{
	const char *json = "";
	appraisal_request request;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_JSON_APPRAISAL_REQUEST_PARSING_ERROR);
}

// Test case for NULL JSON data
TEST(JsonUnmarshalAppraisalRequestTest, NullJsonData)
{
	const char *json = NULL;
	appraisal_request request;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_INVALID_PARAMETER);
}

// Test case for missing quote field
TEST(JsonUnmarshalAppraisalRequestTest, MissingQuoteField)
{
	const char *json = "{ \"user_data\": \"user_data\", \"signed_nonce\": { \"val\": \"nonce_data\", \"iat\": \"iat_data\", \"signature\": \"signature_data\" }, \"policy_ids\": [\"policy1\", \"policy2\"] }";
	appraisal_request request;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_JSON_APPRAISAL_REQUEST_PARSING_ERROR);
}

// Test case for missing user_data field
TEST(JsonUnmarshalAppraisalRequestTest, MissingUserDataField)
{
	const char *json = "{ \"quote\": \"sample_quote\", "
		"  \"verifier_nonce\": { \"val\": \"sample_nonce\",\"iat\": \"sample_iatda\",\"signature\": \"sample_signature\" } "
		"}";
	appraisal_request request;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_JSON_APPRAISAL_REQUEST_PARSING_ERROR);
}

// Test case for missing policy_ids field
TEST(JsonUnmarshalAppraisalRequestTest, MissingPolicyIdsField)
{
	const char *json = "{ \"quote\": \"sample_quote\", "
		"  \"verifier_nonce\": { \"val\": \"sample_nonce\",\"iat\": \"sample_iatda\",\"signature\": \"sample_signature\" }, "
		"  \"runtime_data\": \"sample_user_data\", "
		"  \"policy_ids\": \"\""
		"}";
	appraisal_request request;
	TRUST_AUTHORITY_STATUS status = json_unmarshal_appraisal_request(&request, json);

	EXPECT_EQ(status, STATUS_JSON_INVALID_APPRAISAL_REQUEST_ERROR);
}

TEST(JsonAppraisalRequestMarshalTest, PositiveTest)
{
	appraisal_request request;
	// Initialize the request object with valid data
	// Set the quote
	const char *quote = "This is a quote";
	request.quote_len = strlen(quote);
	request.quote = (uint8_t *)malloc(request.quote_len + 1);

	if (NULL == request.quote)
	{
		ERROR("Error: In memory allocation for request.quote\n");
	}

	memcpy(request.quote, quote, request.quote_len);
	request.quote[request.quote_len] = '\0';

	// Set the nonce
	request.verifier_nonce = (nonce *)malloc(sizeof(nonce));

	if (NULL == request.verifier_nonce)
	{
		ERROR("Error: In memory allocation for request.verifier_nonce\n");
	}

	request.verifier_nonce->val = (uint8_t *)"val";
	request.verifier_nonce->val_len = strlen((const char *)request.verifier_nonce->val);
	request.verifier_nonce->iat = (uint8_t *)"iat";
	request.verifier_nonce->iat_len = strlen((const char *)request.verifier_nonce->iat);
	request.verifier_nonce->signature = (uint8_t *)"Signature";
	request.verifier_nonce->signature_len = strlen((const char *)request.verifier_nonce->signature);

	// Set the user_data
	const char *user_data = "User data";
	request.runtime_data_len = strlen(user_data);
	request.runtime_data = (uint8_t *)malloc(request.runtime_data_len + 1);

	if (NULL == request.runtime_data)
	{
		ERROR("Error: In memory allocation for request.runtime_data\n");
	}

	memcpy(request.runtime_data, user_data, request.runtime_data_len);
	request.runtime_data[request.runtime_data_len] = '\0';

	// Set the policies
	request.policy_ids = (policies *)malloc(sizeof(policies));

	if (NULL == request.policy_ids)
	{
		ERROR("Error: In memory allocation for request.policy_ids\n");
	}

	request.policy_ids->count = 2;
	request.policy_ids->ids = (char **)malloc(sizeof(char *) * request.policy_ids->count);

	if (NULL == request.policy_ids->ids)
	{
		ERROR("Error: In memory allocation for request.policy_ids->ids\n");
	}

	request.policy_ids->ids[0] = strdup("policy1");
	request.policy_ids->ids[1] = strdup("policy2");

	request.event_log = NULL;
	request.event_log_len = 0;

	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_appraisal_request(&request, &json);

	ASSERT_EQ(status, STATUS_OK);

	free(request.quote);
	free(request.verifier_nonce);
	free(request.runtime_data);
	free(request.policy_ids->ids);
	free(request.policy_ids);
	request.quote = NULL;
	request.verifier_nonce = NULL;
	request.runtime_data = NULL;
	request.policy_ids->ids = NULL;
	request.policy_ids = NULL;
}

TEST(JsonAppraisalRequestMarshalTest, EmptyRequestTest)
{
	appraisal_request *request = nullptr;
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_appraisal_request(request, &json);

	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);
}

TEST(JsonAppraisalRequestMarshalTest, EmptyJsonTest)
{
	appraisal_request request;
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_appraisal_request(&request, nullptr);

	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);
}

TEST(JsonAppraisalRequestMarshalTest, NullJsonPointerTest)
{
	appraisal_request request;

	char *json = nullptr;
	TRUST_AUTHORITY_STATUS status = json_marshal_appraisal_request(&request, nullptr);

	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);
	ASSERT_EQ(json, nullptr);
}

// Positive test case
TEST(JsonUnmarshalTokenTest, ValidInput)
{
	// Create an instance of token
	token token;
	// Valid JSON input data
	const char *json = "{\"token\": \"valid_token\"}";
	TRUST_AUTHORITY_STATUS result = json_unmarshal_token(&token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_OK);
}

// Negative test cases
TEST(JsonUnmarshalTokenTest, NullToken)
{
	// Null token
	token *token = nullptr;
	// Valid JSON input data
	const char *json = "{\"token\": \"valid_token\"}";
	TRUST_AUTHORITY_STATUS result = json_unmarshal_token(token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_NULL_TOKEN);
}

TEST(JsonUnmarshalTokenTest, InvalidJson)
{
	// Create an instance of token
	token token;
	// Invalid JSON input data
	const char *json = "invalid_json";
	TRUST_AUTHORITY_STATUS result = json_unmarshal_token(&token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_JSON_TOKEN_PARSING_ERROR);
}

TEST(JsonUnmarshalTokenTest, MissingJwtField)
{
	// Create an instance of token
	token token;
	// JSON input data without "jwt" field
	const char *json = "{}";
	TRUST_AUTHORITY_STATUS result = json_unmarshal_token(&token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_JSON_TOKEN_PARSING_ERROR);
}

TEST(JsonUnmarshalTokenTest, InvalidJwtFieldType)
{
	// Create an instance of token
	token token;
	// JSON input data with invalid type for "jwt" field
	const char *json = "{\"jwt\": 123}";
	TRUST_AUTHORITY_STATUS result = json_unmarshal_token(&token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_JSON_TOKEN_PARSING_ERROR);
}

// Positive test case
TEST(JsonMarshalTokenTest, ValidInput)
{
	// Create an instance of token
	token token;
	strcpy(token.jwt, "valid_token");

	// Initialize the json variable
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS result = json_marshal_token(&token, &json);

	// Assert the result
	ASSERT_EQ(result, STATUS_OK);
	ASSERT_STREQ(json, "{\"token\": \"valid_token\"}");
}

// Negative test cases
TEST(JsonMarshalTokenTest, NullToken)
{
	// Null token
	token *token = nullptr;
	// Initialize the json variable
	char *json = nullptr;
	TRUST_AUTHORITY_STATUS result = json_marshal_token(token, &json);

	// Assert the result
	ASSERT_EQ(result, STATUS_NULL_TOKEN);
	ASSERT_EQ(json, nullptr);
}

TEST(JsonMarshalTokenTest, NullJson)
{
	// Create an instance of token
	token token;
	strcpy(token.jwt, "valid_token");
	// Null json pointer
	char **json = nullptr;
	TRUST_AUTHORITY_STATUS result = json_marshal_token(&token, json);

	// Assert the result
	ASSERT_EQ(result, STATUS_INVALID_PARAMETER);
}
