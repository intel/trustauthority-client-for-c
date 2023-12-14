/* Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <connector.h>
#include <token_provider.h>
#include <gtest/gtest.h>
#include <log.h>
#include <stdlib.h>
#include <types.h>
#include "token_provider_mock_test.h"
#include "mock_server.h"

extern std::mutex mockServerMutex;

int mock_adapter_new(evidence_adapter ** adapter, 
		int eid, 
		void *report_function)
{
	mock_adapter_context *ctx = NULL;

	*adapter = (evidence_adapter *) malloc(sizeof(evidence_adapter));

	if (NULL == adapter)
	{
		ERROR("Error: In memory allocation for adapter\n");
	}

	ctx = (mock_adapter_context *) calloc(1, sizeof(mock_adapter_context));

	if (NULL == ctx)
	{
		ERROR("Error: In memory allocation for context\n");
	}

	ctx->eid = eid;
	ctx->report_callback = report_function;
	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = mock_collect_evidence;

	return STATUS_OK;
}

int mock_collect_evidence(void *ctx,
		evidence * evidence,
		nonce * nonce,
		uint8_t * user_data, 
		uint32_t user_data_len)
{
	evidence->type = EVIDENCE_TYPE_SGX;

	// Populating Evidence with random data
	evidence->evidence = (uint8_t *) calloc(1, 5);

	if (NULL == evidence->evidence) 
	{
		ERROR("Error: In memory allocation for mock quote\n");
	}

	evidence->evidence = (uint8_t *) "test";
	evidence->evidence_len = 5;

	// Populating Evidence with UserData
	evidence->user_data = (uint8_t *) calloc(1, 5);

	if (NULL == evidence->user_data)
	{
		ERROR("Error: In memory allocation for mock user data\n");
	}

	evidence->user_data = (uint8_t *) "test";
	evidence->user_data_len = user_data_len;

	return STATUS_OK;
}

TEST(CollectToken, ApiNullParameters)
{
	trust_authority_connector api;
	token token;
	policies policies;
	evidence_adapter *adapter;
	uint8_t *user_data;
	uint32_t user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	mock_adapter_new(&adapter, 10, NULL);

	TRUST_AUTHORITY_STATUS status = collect_token(NULL, NULL, &token, &policies, NULL, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_CONNECTOR);
}

TEST(CollectToken, TokenNullError)
{
	trust_authority_connector api;
	token token;
	policies policies;
	evidence_adapter *adapter;
	uint8_t *user_data;
	uint32_t user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	mock_adapter_new(&adapter, 10, NULL);

	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"val_len\":20,\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"iat_len\":20,\"signature\":\"SGVsbG8sIFdvcmxkIW==\",\"signature_len\":20}");
	mockServer.start();

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8080", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, NULL, &policies, NULL, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_TOKEN);

	mockServer.stop();
}

TEST(CollectToken, NullCtxParamater)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter;
	uint8_t *user_data;
	uint32_t user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	policies policiesObj;
	policies *policies = &policiesObj;
	policies->count = 1;
	policies->ids = new char *[1];
	policies->ids[0] = new char[10];
	strncpy(policies->ids[0], "policy1", 10);

	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"val_len\":20,\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"iat_len\":20,\"signature\":\"SGVsbG8sIFdvcmxkIW==\",\"signature_len\":20}");
	mockServer.start();

	mock_adapter_new(&adapter, 10, NULL);
	adapter->ctx = NULL;

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8080", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, &token, policies, NULL, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);

	mockServer.stop();
}

TEST(CollectToken, NullNonceError)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter;
	uint8_t *user_data;
	uint32_t user_data_len = 0;

	policies policiesObj;
	policies *policies = &policiesObj;
	policies->count = 1;
	policies->ids = new char *[1];
	policies->ids[0] = new char[10];
	strncpy(policies->ids[0], "policy1", 10);

	mock_adapter_new(&adapter, 10, NULL);

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8080", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, &token, policies, NULL, adapter, user_data, user_data_len);

	ASSERT_EQ(status, STATUS_GET_NONCE_ERROR);
}

TEST(CollectToken, ValidData)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter;
	uint8_t *user_data;
	uint32_t user_data_len = 0;
	response_headers headers = { 0 };

	policies policiesObj;
	policies *policies = &policiesObj;
	policies->count = 1;
	policies->ids = new char *[1];
	policies->ids[0] = new char[10];
	strncpy(policies->ids[0], "policy1", 10);

	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"val_len\":20,\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"iat_len\":20,\"signature\":\"SGVsbG8sIFdvcmxkIW==\",\"signature_len\":20}");
	mockServer.start();

	mock_adapter_new(&adapter, 10, NULL);

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8080", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	TRUST_AUTHORITY_STATUS status = collect_token(&api, &headers, &token, policies, NULL, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_OK);

	free(token.jwt);
	token.jwt = NULL;

	mockServer.stop();
}
