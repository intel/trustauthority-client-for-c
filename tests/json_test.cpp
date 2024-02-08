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