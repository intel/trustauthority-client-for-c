/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tdx_adapter.h>
#include <types.h>
#include <tdx_attest.h>
#include <openssl/evp.h>
#include <log.h>

/**
 * callback to get TDX report
 */
typedef tdx_attest_error_t (*tdx_get_quote_fx)(const tdx_report_data_t *p_tdx_report_data,
		const tdx_uuid_t att_key_id_list[],
		uint32_t list_size,
		tdx_uuid_t *p_att_key_id,
		uint8_t **pp_quote,
		uint32_t *p_quote_size,
		uint32_t flags);

int tdx_adapter_new(evidence_adapter **adapter)
{
	tdx_adapter_context *ctx = NULL;
	if (NULL == adapter)
	{
		return STATUS_TDX_ERROR_BASE | STATUS_NULL_ADAPTER;
	}

	*adapter = (evidence_adapter *)malloc(sizeof(evidence_adapter));
	if (NULL == *adapter)
	{
		return STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx = (tdx_adapter_context *)calloc(1, sizeof(tdx_adapter_context));
	if (NULL == ctx)
	{
		free(*adapter);
		*adapter = NULL;
		return STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}
	ctx->tdx_att_get_quote_cb = tdx_att_get_quote;

	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = tdx_collect_evidence;

	return STATUS_OK;
}

int tdx_adapter_free(evidence_adapter *adapter)
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

int tdx_collect_evidence(void *ctx,
		evidence *evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	tdx_adapter_context *tdx_ctx = NULL;
	if (NULL == ctx)
	{
		return STATUS_TDX_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
	}

	if (NULL == evidence)
	{
		return STATUS_TDX_ERROR_BASE | STATUS_NULL_EVIDENCE;
	}

	if (user_data_len > 0 && user_data == NULL)
	{
		return STATUS_TDX_ERROR_BASE | STATUS_INVALID_USER_DATA;
	}

	tdx_ctx = (tdx_adapter_context *)ctx;
	uint32_t nonce_data_len = 0;
	uint8_t *nonce_data = NULL;

	if (NULL != nonce)
	{
		if (nonce->val == NULL)
		{
			return STATUS_TDX_ERROR_BASE | STATUS_NULL_NONCE;
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

	// Hashing Nonce and UserData
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	int status = STATUS_OK;
	const EVP_MD *md = EVP_get_digestbyname("sha512");
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, nonce_data, nonce_data_len);
	EVP_DigestUpdate(mdctx, user_data, user_data_len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	// Fetching Quote from TD
	uint32_t quote_size = 0;
	uint8_t *p_quote_buf = NULL;
	tdx_report_data_t report_data = {{0}};
	tdx_uuid_t selected_att_key_id = {0};
	memcpy(report_data.d, md_value, TDX_REPORT_DATA_SIZE);

	if (tdx_ctx->tdx_att_get_quote_cb == NULL)
	{
		ERROR("Error: callback function is empty");
		status = STATUS_TDX_ERROR_BASE;
		goto ERROR;
	}

	uint32_t ret = ((tdx_get_quote_fx)tdx_ctx->tdx_att_get_quote_cb)(&report_data, NULL, 0, &selected_att_key_id, &p_quote_buf, &quote_size, 0);
	if (TDX_ATTEST_SUCCESS != ret)
	{
		ERROR("Error: In tdx_att_get_quote. 0x%04x\n", ret);
		status = ret;
		goto ERROR;
	}

	evidence->type = EVIDENCE_TYPE_TDX;
	// Populating Evidence with TDQuote
	evidence->evidence = (uint8_t *)calloc(quote_size, sizeof(uint8_t));
	if (NULL == evidence->evidence)
	{
		status = STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(evidence->evidence, p_quote_buf, quote_size);
	evidence->evidence_len = quote_size;
	tdx_att_free_quote(p_quote_buf);

	// Populating Evidence with UserData
	evidence->runtime_data = (uint8_t *)calloc(user_data_len, sizeof(uint8_t));
	if (NULL == evidence->runtime_data)
	{
		free(evidence->evidence);
		evidence->evidence = NULL;
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(evidence->runtime_data, user_data, user_data_len);
	evidence->runtime_data_len = user_data_len;
	evidence->event_log = NULL;
	evidence->event_log_len = 0;

ERROR:
	if (nonce_data)
	{
		free(nonce_data);
		nonce_data = NULL;
	}
	return status;
}
