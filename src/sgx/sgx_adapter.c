/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sgx_adapter.h>
#include <types.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>
#include <log.h>


int sgx_adapter_new(evidence_adapter **adapter,
		int eid,
		void *report_function)
{
	sgx_adapter_context *ctx = NULL;

	if (NULL == adapter)
	{
		return STATUS_SGX_ERROR_BASE | STATUS_NULL_ADAPTER;
	}

	*adapter = (evidence_adapter *)malloc(sizeof(evidence_adapter));
	if (NULL == *adapter)
	{
		return STATUS_SGX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx = (sgx_adapter_context *)calloc(1, sizeof(sgx_adapter_context));
	if (NULL == ctx)
	{
		free(*adapter);
		*adapter = NULL;
		return STATUS_SGX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx->eid = eid;
	ctx->report_callback = report_function;
	ctx->sgx_qe_target_info_cb = sgx_qe_get_target_info;
	ctx->sgx_qe_get_quote_size_cb = sgx_qe_get_quote_size;
	ctx->sgx_qe_get_quote_cb = sgx_qe_get_quote;
	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = sgx_collect_evidence;

	return STATUS_OK;
}

int sgx_collect_evidence(void *ctx,
		evidence *evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	sgx_adapter_context *sgx_ctx = NULL;
	uint32_t nonce_data_len = 0;
	uint8_t *nonce_data = NULL;

	if (NULL == ctx)
	{
		return STATUS_SGX_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
	}

	if (NULL == evidence)
	{
		return STATUS_SGX_ERROR_BASE | STATUS_NULL_EVIDENCE;
	}

	if (user_data_len > 0 && user_data == NULL)
	{
		return STATUS_SGX_ERROR_BASE | STATUS_INVALID_USER_DATA;
	}

	if (NULL != nonce)
	{
		if (nonce->val == NULL)
		{
			return STATUS_SGX_ERROR_BASE | STATUS_NULL_NONCE;
		}
		// append nonce->val and nonce->iat
		nonce_data_len = nonce->val_len + nonce->iat_len;
		nonce_data = (uint8_t *)calloc(1, (nonce_data_len + 1) * sizeof(uint8_t));
		if (NULL == nonce_data)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		
		memcpy(nonce_data, nonce->val, nonce->val_len);
		memcpy(nonce_data + nonce->val_len, nonce->iat, nonce->iat_len);
	}

	sgx_ctx = (sgx_adapter_context *)ctx;

	int status = 0;
	uint32_t retval = 0;
	uint32_t quote_size = 0;
	uint8_t *p_quote_buffer = NULL;
	quote3_error_t qe3_ret;
	sgx_target_info_t qe_target_info;
	sgx_report_t app_report;

	if  ( sgx_ctx->sgx_qe_target_info_cb == NULL || sgx_ctx->report_callback == NULL ||  sgx_ctx->sgx_qe_get_quote_size_cb == NULL || sgx_ctx->sgx_qe_get_quote_cb == NULL )
	{
		ERROR("Error: Callback function is null");
		status = STATUS_NULL_CALLBACK;
		goto ERROR;
	}

	qe3_ret = sgx_ctx->sgx_qe_target_info_cb(&qe_target_info);
	if (0 != qe3_ret)
	{
		ERROR("Error: In sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
		status  = qe3_ret;
		goto ERROR;
	}


	status = ((report_fx)sgx_ctx->report_callback)(sgx_ctx->eid, &retval, &qe_target_info, nonce_data,
			nonce_data_len, &app_report);
	if (0 != status)
	{
		ERROR("Error: Report callback returned error code  0x%04x\n", status);
		goto ERROR;
	}

	if (0 != retval)
	{
		ERROR("Error: Report retval returned 0x%04x\n", retval);
		status = retval;
		goto ERROR;
	}

	qe3_ret = sgx_ctx->sgx_qe_get_quote_size_cb(&quote_size);
	if (0 != qe3_ret)
	{
		ERROR("Error: In sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
		status = qe3_ret;
		goto ERROR;
	}

	p_quote_buffer = (uint8_t *)calloc(1, (quote_size + 1) * sizeof(uint8_t));
	if (NULL == p_quote_buffer)
	{
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memset(p_quote_buffer, 0, quote_size);

	qe3_ret = sgx_ctx->sgx_qe_get_quote_cb(&app_report, quote_size, p_quote_buffer);
	if (qe3_ret != 0)
	{
		ERROR("Error: In sgx_qe_get_quote. 0x%04x\n", qe3_ret);
		status = qe3_ret;
		goto ERROR;
	}

	evidence->type = EVIDENCE_TYPE_SGX;

	// Populating Evidence with SQXQuote
	evidence->evidence = (uint8_t *)calloc(quote_size + 1, sizeof(uint8_t));
	if (NULL == evidence->evidence)
	{
		status = STATUS_SGX_ERROR_BASE | STATUS_ALLOCATION_ERROR; 
		goto ERROR;
	}
	memcpy(evidence->evidence, p_quote_buffer, quote_size);
	evidence->evidence_len = quote_size;

	// Populating Evidence with UserData
	evidence->user_data = (uint8_t *)calloc(user_data_len, sizeof(uint8_t));
	if (NULL == evidence->user_data)
	{
		
		free(evidence->evidence);
		evidence->evidence = NULL;
		status = STATUS_SGX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(evidence->user_data, user_data, user_data_len);
	evidence->user_data_len = user_data_len;
	evidence->event_log=NULL;
	evidence->event_log_len=0;

ERROR:
	if (p_quote_buffer != NULL)
	{
		free(p_quote_buffer);
		p_quote_buffer = NULL;
	}
	if (nonce_data != NULL)
	{
		free(nonce_data);
		nonce_data = NULL;
	}
	return status;
}

int sgx_adapter_free(evidence_adapter *adapter)
{
	if (NULL == adapter)
	{
		return STATUS_NULL_ADAPTER;
	}
	
	if (NULL != adapter->ctx)
	{
		free(adapter->ctx);
		adapter->ctx = NULL;
	}

	free(adapter);
	adapter = NULL;
	return STATUS_OK;
}
