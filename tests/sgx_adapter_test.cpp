#include <gtest/gtest.h>
#include <stdint.h>
#include <stdlib.h>
#include <log.h>
#include <stdio.h>
#include <string.h>
#include <types.h>
#include <sgx_adapter.h>
#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>

TEST(SgxAdapterTest, PositiveCase)
{
	evidence_adapter *adapter = nullptr;
	int eid = 123;
	void *report_function = nullptr;

	// Valid input parameters
	int result = sgx_adapter_new(&adapter, eid, report_function);
	ASSERT_EQ(result, STATUS_OK);
	ASSERT_NE(adapter, nullptr);
	ASSERT_NE(adapter->ctx, nullptr);
	ASSERT_EQ(adapter->collect_evidence, sgx_collect_evidence);

	// Cleanup
	free(adapter->ctx);
	free(adapter);
}

TEST(SgxAdapterTest, NegativeCase_NullAdapter)
{
	int eid = 123;
	void *report_function = nullptr;

	// Null adapter pointer
	int result = sgx_adapter_new(nullptr, eid, report_function);

	ASSERT_EQ(result, STATUS_SGX_ERROR_BASE | STATUS_NULL_ADAPTER);
}

// Test case to free sgx_adapter - Success case
TEST(FreeSgxAdapter, SuccessCase)
{

	evidence_adapter *adapter = NULL;
	adapter = (evidence_adapter *) calloc(1, sizeof(evidence_adapter));

	if (NULL == adapter)
	{
		ERROR("Error: In memory allocation for adapter\n");
	}

	int result = sgx_adapter_free(adapter);

	// Result should be STATUS_ok
	ASSERT_EQ(result, STATUS_OK);
}

// Negative test case - ctx is null
TEST(SgxCollectEvidenceTest, TestSgxCtxNull)
{
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

	uint8_t user_data[] = { 0x01, 0x02, 0x03 };
	uint32_t user_data_len = sizeof(user_data);

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(NULL, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_SGX_ERROR_BASE | STATUS_NULL_ADAPTER_CTX);

	free(evidence.evidence);
}

// Negative test case - Evidence is null
TEST(SgxCollectEvidenceTest, TestSgxEvidenceNUll)
{
	nonce nonce;
	nonce.val = NULL;
	nonce.val_len = 0;
	nonce.iat = NULL;
	nonce.iat_len = 0;
	nonce.signature = NULL;
	nonce.signature_len = 0;

	sgx_adapter_context ctx;
	ctx.eid = 1234;

	uint8_t user_data[] = { 0x01, 0x02, 0x03 };
	uint32_t user_data_len = sizeof(user_data);

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(&ctx, NULL, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_SGX_ERROR_BASE | STATUS_NULL_EVIDENCE);
}

// Negative test case - nonce is null
TEST(SgxCollectEvidenceTest, TestSgxNonceNull)
{
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

	sgx_adapter_context ctx;
	ctx.eid = 1234;

	uint8_t user_data[] = { 0x01, 0x02, 0x03 };
	uint32_t user_data_len = sizeof(user_data);

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(&ctx, &evidence, &nonce, user_data, user_data_len);

	// Assertions
	ASSERT_EQ(result, STATUS_SGX_ERROR_BASE | STATUS_NULL_NONCE);

	free(evidence.evidence);
}

// Negative test case - user data is null
TEST(SgxCollectEvidenceTest, TestSgxUserDataNull)
{
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

	sgx_adapter_context ctx;
	ctx.eid = 1234;

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(&ctx, &evidence, &nonce, NULL, 10);

	// Assertions
	ASSERT_EQ(result, STATUS_SGX_ERROR_BASE | STATUS_INVALID_USER_DATA);

	free(evidence.evidence);
}
sgx_status_t report_callback_mock(sgx_enclave_id_t eid,
                        uint32_t *retval,
                        const sgx_target_info_t *p_qe3_target,
                        uint8_t *nonce,
                        uint32_t nonce_size,
                        sgx_report_t *p_report) 
{
	return (sgx_status_t)0;
}
quote3_error_t sgx_qe_target_info_mock(sgx_target_info_t *p_target_info)
{
	return (quote3_error_t)0;
}

quote3_error_t sgx_qe_target_info_fail_mock(sgx_target_info_t *p_target_info)
{
	return (quote3_error_t)3;
}
quote3_error_t sgx_qe_get_quote_size_mock(uint32_t *p_quote_size)
{
	*p_quote_size = 5;
	return (quote3_error_t)0;
}
quote3_error_t sgx_qe_get_quote_mock(const sgx_report_t *p_app_report, 
			uint32_t quote_size, 
			uint8_t *p_quote) {
	return (quote3_error_t)0;
}

// Negative test case - sgx_qe_get_target_info failure
TEST(SgxCollectEvidenceTest, TestGetSgxqeGetTargetInfoFailure)
{
	evidence evidence;
	evidence.evidence = NULL;
	evidence.evidence_len = 0;
	evidence.user_data_len = 5;

	nonce nonce;
	nonce.val = new uint8_t[10];
	strncpy((char *) nonce.val, "data1", 6);
	nonce.val_len = 6;
	nonce.iat = new uint8_t[10];
	strncpy((char *) nonce.iat, "data1", 6);
	nonce.iat_len = 6;
	nonce.signature = NULL;
	nonce.signature_len = 10;

	sgx_adapter_context ctx;
	ctx.eid = 1234;
	ctx.sgx_qe_target_info_cb = sgx_qe_target_info_fail_mock;
	ctx.sgx_qe_get_quote_size_cb = sgx_qe_get_quote_size;
	ctx.sgx_qe_get_quote_cb = sgx_qe_get_quote;

	uint8_t *u_data = NULL;
	u_data = new uint8_t[10];
	strncpy((char *) u_data, "data1", 6);

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(&ctx, &evidence, &nonce, u_data, 10);

	// Assertions
	ASSERT_NE(result, 0);

	free(evidence.evidence);
}

// Postive test case
TEST(SgxCollectEvidenceTest, TestValidSgx)
{
	evidence evidence;
	evidence.evidence = NULL;
	evidence.evidence_len = 0;
	evidence.user_data_len = 5;

	nonce nonce;
	nonce.val = new uint8_t[10];
	strncpy((char *) nonce.val, "data1", 6);
	nonce.val_len = 6;
	nonce.iat = new uint8_t[10];
	strncpy((char *) nonce.iat, "data1", 6);
	nonce.iat_len = 6;
	nonce.signature = NULL;
	nonce.signature_len = 10;

	sgx_adapter_context ctx;
	ctx.eid = 1234;
	ctx.report_callback = (void *)report_callback_mock;
	ctx.sgx_qe_target_info_cb = sgx_qe_target_info_mock;
	ctx.sgx_qe_get_quote_size_cb = sgx_qe_get_quote_size_mock;
	ctx.sgx_qe_get_quote_cb = sgx_qe_get_quote_mock;

	uint8_t *u_data = NULL;
	u_data = new uint8_t[10];
	strncpy((char *) u_data, "data1", 6);

	// Call the sgx_collect_evidence function
	int result = sgx_collect_evidence(&ctx, &evidence, &nonce, u_data, 10);

	// Assertions
	ASSERT_EQ(result, 0);

	free(evidence.evidence);
}

