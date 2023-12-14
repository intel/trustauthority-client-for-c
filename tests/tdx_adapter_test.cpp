/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <tdx_adapter.h>
#include <types.h>
#include <tdx_attest.h>
#include <openssl/rand.h>
#include <log.h>
#include <gtest/gtest.h>

tdx_attest_error_t tdx_att_get_quote_mock(const tdx_report_data_t *
		p_tdx_report_data,
		const tdx_uuid_t
		att_key_id_list[],
		uint32_t list_size,
		tdx_uuid_t * p_att_key_id,
		uint8_t ** pp_quote,
		uint32_t * p_quote_size,
		uint32_t flags)
{

	uint8_t dummy_data[] = { 0x01, 0x02, 0x03 };
	uint32_t dummy_data_len = sizeof(dummy_data);
	*p_quote_size = dummy_data_len;
	*pp_quote = (uint8_t *) calloc(1, *p_quote_size);
	if (NULL == *pp_quote)
	{
		return TDX_ATTEST_ERROR_OUT_OF_MEMORY;
	}
	memcpy(*pp_quote, dummy_data, *p_quote_size);

	return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_get_quote_fail_mock(const tdx_report_data_t *
		p_tdx_report_data,
		const tdx_uuid_t
		att_key_id_list[],
		uint32_t list_size,
		tdx_uuid_t * p_att_key_id,
		uint8_t ** pp_quote,
		uint32_t * p_quote_size,
		uint32_t flags)
{
	return TDX_ATTEST_ERROR_OUT_OF_MEMORY;
}

TEST(CreateTDXAdapter, NullAdapterPointer)
{
	int result = tdx_adapter_new(NULL);

	// Verify the result
	EXPECT_EQ((STATUS_TDX_ERROR_BASE | STATUS_NULL_ADAPTER), result);
}

TEST(CreateTDXAdapter, ValidAdapterPointer)
{
	// Prepare test data
	evidence_adapter *adapter = NULL;
	// Call the function to be tested
	int result = tdx_adapter_new(&adapter);

	// Verify the result
	EXPECT_EQ(STATUS_OK, result);
}

// Test case to free tdx_adapter - failure case
TEST(FreeTdxAdapter, Failurecase)
{
	int result = tdx_adapter_free(NULL);

	// Result should be adapter is null
	ASSERT_EQ(result, STATUS_NULL_ADAPTER);
}

// Test case to free tdx_adapter - Success case
TEST(FreeTdxAdapter, SuccessCase)
{
	evidence_adapter *adapter = NULL;
	adapter = (evidence_adapter *) calloc(1, sizeof(evidence_adapter));

	if (NULL == adapter)
	{
		ERROR("Error: In memory allocation for adapter\n");
	}

	int result = tdx_adapter_free(adapter);

	// Result should be status_ok
	ASSERT_EQ(result, STATUS_OK);
}

// Negative test case - ctx is null
TEST(TdxCollectEvidenceTest, TestTdxCtxNull)
{
	// Prepare the necessary input for sgx_collect_evidence
	evidence evidence;
	nonce nonce;
	uint8_t user_data[] = { 0x01, 0x02, 0x03 };	// Set an example user data
	uint32_t user_data_len = sizeof(user_data);

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(NULL, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_TDX_ERROR_BASE | STATUS_NULL_ADAPTER_CTX);
}

// Negative test case - Evidence is null
TEST(TdxCollectEvidenceTest, TestTdxEvidenceNUll)
{
	// Prepare the necessary input for tdx_collect_evidence
	nonce nonce;
	tdx_adapter_context ctx;
	uint8_t user_data[] = { 0x01, 0x02, 0x03 };	// Set an example user data
	uint32_t user_data_len = sizeof(user_data);

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(&ctx, NULL, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_TDX_ERROR_BASE | STATUS_NULL_EVIDENCE);
}

// Negative test case - nonce is null
TEST(TdxCollectEvidenceTest, TestTdxNonceNull)
{
	// Prepare the necessary input for tdx_collect_evidence
	evidence evidence;
	evidence.evidence = NULL;
	evidence.evidence_len = 0;
	evidence.user_data = NULL;
	evidence.user_data_len = 0;

	nonce nonce;
	nonce.val = NULL;
	nonce.val_len = 0;
	nonce.iat = NULL;
	nonce.iat_len = 0;
	nonce.signature = NULL;
	nonce.signature_len = 0;

	tdx_adapter_context ctx;
	uint8_t user_data[] = { 0x01, 0x02, 0x03 };	// Set an example user data
	uint32_t user_data_len = sizeof(user_data);

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(&ctx, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_TDX_ERROR_BASE | STATUS_NULL_NONCE);
}

// Negative test case - userdata is null
TEST(TdxCollectEvidenceTest, TestTdxUserDataNull)
{
	// Prepare the necessary input for tdx_collect_evidence
	evidence evidence;
	evidence.evidence = NULL;
	evidence.evidence_len = 0;
	evidence.user_data = NULL;
	evidence.user_data_len = 0;

	nonce nonce;
	nonce.val = NULL;
	nonce.val_len = 0;
	nonce.iat = NULL;
	nonce.iat_len = 0;
	nonce.signature = NULL;
	nonce.signature_len = 0;

	tdx_adapter_context ctx;

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(&ctx, &evidence, &nonce, NULL, 10);

	// Assertions
	ASSERT_EQ(result, STATUS_TDX_ERROR_BASE | STATUS_INVALID_USER_DATA);
}

int generate_nonce(unsigned char *nonce, size_t size)
{
	if (RAND_bytes(nonce, size) != 1) {
		// Error occured
		printf("Test: Error in generating nonce\n");
		return 1;
	}
	return 0;
}

// Negative case
TEST(TdxCollectEvidenceTest, TestInvalidTdxData)
{
	// Prepare the necessary input for tdx_collect_evidence
	evidence evidence = { 0 };
	nonce nonce = { 0 };
	nonce.val = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.val)
	{
		ERROR("Error: In memory allocation for nonce.val\n");
	}

	nonce.val_len = 12;
	if (generate_nonce(nonce.val, nonce.val_len) != 0) {
		printf("Error in nonce\n");
		return;
	}

	nonce.iat = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.iat)
	{
		ERROR("Error: In memory allocation for nonce.iat\n");
	}

	nonce.iat_len = 12;
	nonce.signature = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.signature)
	{
		ERROR("Error: In memory allocation for nonce.signature\n");
	}

	nonce.signature_len = 12;

	tdx_adapter_context *ctx = NULL;
	ctx = (tdx_adapter_context *) calloc(1, sizeof(tdx_adapter_context));

	if (NULL == ctx)
	{
		ERROR("Error: In memory allocation for ctx\n");
	}
	ctx->tdx_att_get_quote_cb = tdx_att_get_quote_fail_mock;

	uint8_t user_data[] = { 0x01, 0x02, 0x03 };	// Set an example user data
	uint32_t user_data_len = sizeof(user_data);

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(ctx, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_NE(result, TDX_ATTEST_SUCCESS);

	free(nonce.val);
	nonce.val = NULL;
	free(nonce.iat);
	nonce.iat = NULL;
	free(nonce.signature);
	nonce.signature = NULL;
	free(ctx);
	ctx = NULL;
}

// Positive test
TEST(TdxCollectEvidenceTest, TestValidTdxData)
{
	// Prepare the necessary input for tdx_collect_evidence
	evidence evidence = { 0 };
	nonce nonce = { 0 };
	nonce.val = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.val)
	{
		ERROR("Error: In memory allocation for nonce.val\n");
	}

	nonce.val_len = 12;
	if (generate_nonce(nonce.val, nonce.val_len) != 0) {
		printf("Error in nonce\n");
		return;
	}

	nonce.iat = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.iat)
	{
		ERROR("Error: In memory allocation for nonce.iat\n");
	}

	nonce.iat_len = 12;
	nonce.signature = (uint8_t *) calloc(1, 12);

	if (NULL == nonce.signature)
	{
		ERROR("Error: In memory allocation for nonce.signature\n");
	}
	nonce.signature_len = 12;

	tdx_adapter_context *ctx = NULL;
	ctx = (tdx_adapter_context *) calloc(1, sizeof(tdx_adapter_context));
	if (NULL == ctx)
	{
		ERROR("Error: In memory allocation for context\n");
	}
	ctx->tdx_att_get_quote_cb = tdx_att_get_quote_mock;

	uint8_t user_data[] = { 0x01, 0x02, 0x03 };	// Set an example user data
	uint32_t user_data_len = sizeof(user_data);

	// Call the tdx_collect_evidence function
	int result = tdx_collect_evidence(ctx, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_OK);

	free(nonce.val);
	nonce.val = NULL;
	free(nonce.iat);
	nonce.iat = NULL;
	free(nonce.signature);
	nonce.signature = NULL;
	free(ctx);
	ctx = NULL;
}
