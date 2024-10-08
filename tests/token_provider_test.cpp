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
void mock_adapter_free(evidence_adapter *adapter)
{
	if(NULL != adapter){
		if(NULL != adapter->ctx)
		{
			free(adapter->ctx);
			adapter->ctx = NULL;
		}
		free(adapter);
		adapter = NULL;
	}
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

	memcpy(evidence->evidence,  (uint8_t *) "test", 4);
	evidence->evidence_len = 5;

	// Populating Evidence with UserData
	evidence->user_data = (uint8_t *) calloc(1, 5);

	if (NULL == evidence->user_data)
	{
		ERROR("Error: In memory allocation for mock user data\n");
	}

	memcpy(evidence->user_data, (uint8_t*)"test", 4);
	evidence->user_data_len = user_data_len;

	return STATUS_OK;
}

TEST(CollectToken, ApiNullParameters)
{
	trust_authority_connector api;
	token token;
	policies policies;
	evidence_adapter *adapter = NULL;
	uint8_t *user_data = NULL;
	uint32_t user_data_len = 5;
	collect_token_args token_args ={0};

	token_args.policies = &policies;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	mock_adapter_new(&adapter, 10, NULL);

	TRUST_AUTHORITY_STATUS status = collect_token(NULL, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_CONNECTOR);

	status = collect_token_azure(NULL, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_CONNECTOR);

	delete[] user_data;
	mock_adapter_free(adapter);
}

TEST(CollectToken, TokenNullError)
{
	trust_authority_connector api;
	token token;
	policies policies;
	evidence_adapter *adapter = NULL;
	uint8_t *user_data = NULL;
	uint32_t user_data_len = 5;
	user_data = new uint8_t[10];
	collect_token_args token_args ={0};
	strncpy((char *) user_data, "data1", 6);

	mock_adapter_new(&adapter, 10, NULL);

	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"val_len\":20,\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"iat_len\":20,\"signature\":\"SGVsbG8sIFdvcmxkIW==\",\"signature_len\":20}");
	mockServer.start();

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8081", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token_args.policies = &policies;
	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, NULL, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_TOKEN);

	status = collect_token_azure(&api, NULL, NULL, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_NULL_TOKEN);
	delete[] user_data;
	mock_adapter_free(adapter);
	mockServer.stop();
}

TEST(CollectToken, NullCtxParamater)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter = NULL;
	uint8_t *user_data = NULL;
	uint32_t user_data_len = 5;
	collect_token_args token_args ={0};

	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	policies policiesObj;
	policies *policies = &policiesObj;
	policies->count = 1;
	policies->ids = new char *[1];
	policies->ids[0] = new char[10];
	strncpy(policies->ids[0], "policy1", 10);
	token_args.policies = policies;

	// Start the mock server
	MockServer
		mockServer
		("{\"val\":\"SGVsbG8sIFdvcmxkIW==\",\"val_len\":20,\"iat\":\"SGVsbG8sIFdvcmxkIW==\",\"iat_len\":20,\"signature\":\"SGVsbG8sIFdvcmxkIW==\",\"signature_len\":20}");
	mockServer.start();

	mock_adapter_new(&adapter, 10, NULL);
	adapter->ctx = NULL;

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8081", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);

	status = collect_token_azure(&api, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_INVALID_PARAMETER);

	mock_adapter_free(adapter);
	token_free(&token);
	delete[] user_data;
	mockServer.stop();
}

TEST(CollectToken, NullNonceError)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter = NULL;
	uint8_t *user_data = NULL;
	uint32_t user_data_len = 0;

	policies policiesObj;
	collect_token_args token_args = {0};
	policies *policies = &policiesObj;
	policies->count = 1;
	policies->ids = new char *[1];
	policies->ids[0] = new char[10];
	strncpy(policies->ids[0], "policy1", 10);

	mock_adapter_new(&adapter, 10, NULL);

	// Prepare test data
	strncpy(api.api_url, "http://localhost:8081", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);
	token_args.policies = policies;

	TRUST_AUTHORITY_STATUS status = collect_token(&api, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_GET_NONCE_ERROR);

	status = collect_token_azure(&api, NULL, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_GET_NONCE_ERROR);

	mock_adapter_free(adapter);
	token_free(&token);
	delete[] user_data;
}

TEST(CollectToken, ValidData)
{
	trust_authority_connector api;
	token token;
	evidence_adapter *adapter = NULL;
	uint8_t *user_data = NULL;
	uint32_t user_data_len = 0;
	response_headers headers = { 0 };
	collect_token_args token_args = {0};

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
	strncpy(api.api_url, "http://localhost:8081", API_URL_MAX_LEN);
	strncpy(api.api_key, "your_api_key", API_KEY_MAX_LEN);

	token.jwt = (char *) malloc(100 * sizeof(char));

	if (NULL == token.jwt)
	{
		ERROR("Error: In memory allocation for jwt\n");
	}

	user_data_len = 5;
	user_data = new uint8_t[10];
	strncpy((char *) user_data, "data1", 6);

	token_args.policies = policies;
	TRUST_AUTHORITY_STATUS status = collect_token(&api, &headers, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_OK);

	status = collect_token_azure(&api, &headers, &token, &token_args, adapter, user_data, user_data_len);
	ASSERT_EQ(status, STATUS_OK);

	mock_adapter_free(adapter);
	token_free(&token);
	delete[] user_data;
	mockServer.stop();
}
