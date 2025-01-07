/*
 * Copyright (C) 2023-2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tdx_adapter.h>
#include <types.h>
#include <openssl/evp.h>
#include <log.h>
#include <json.h>
#include <report.h>

/**
 * callback to get TDX report
 */
typedef TRUST_AUTHORITY_STATUS (*tdx_get_quote_fx)(Request *req, Response **res);

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
	ctx->tdx_att_get_quote_cb = get_report;

	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = tdx_collect_evidence;
	(*adapter)->get_evidence = tdx_get_evidence;
	(*adapter)->get_evidence_identifier = tdx_get_evidence_identifier;

	return STATUS_OK;
}

int tdx_adapter_free(evidence_adapter *adapter)
{
	if (NULL != adapter)
	{
		if (NULL != adapter->ctx)
		{
			free(adapter->ctx);
			adapter->ctx = NULL;
		}
		free(adapter);
		adapter = NULL;
	}
	return STATUS_OK;
}

const char* tdx_get_evidence_identifier() {
	return EVIDENCE_IDENTIFIER_TDX;
}

int tdx_get_evidence(void *ctx,
		json_t *jansson_evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	int result = 0;
	evidence evidence = {0};
	json_t *jansson_nonce = NULL;

	result = tdx_collect_evidence(ctx, &evidence, nonce, user_data, user_data_len);
	if (result != STATUS_OK)
	{
		return result;
	}

	result = get_jansson_evidence(&evidence, &jansson_evidence);
	if (result != STATUS_OK)
	{
		ERROR("Error: Failed to create evidence json: 0x%04x\n", result);
		return result;
	}

	if (nonce != NULL) {
		result = get_jansson_nonce(nonce, &jansson_nonce);
		if (result != STATUS_OK)
		{
			ERROR("Error: Failed to create nonce json: 0x%04x\n", result);
			goto ERROR;
		}

		json_object_set(jansson_evidence, "verifier_nonce", jansson_nonce);
	}

ERROR:
	if (jansson_nonce)
	{
		json_decref(jansson_nonce);
		jansson_nonce = NULL;
	}
	return result;
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
			return STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
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

	Request req = {
		.in_blob = md_value,
		.in_blob_size = TDX_REPORT_DATA_SIZE,
		.get_aux_blob = 0
	};

	if (tdx_ctx->tdx_att_get_quote_cb == NULL)
	{
		status = STATUS_TDX_ERROR_BASE | STATUS_NULL_CALLBACK;
		goto ERROR;
	}

	Response *res = NULL;
	status = ((tdx_get_quote_fx)tdx_ctx->tdx_att_get_quote_cb)(&req, &res);
	if (status != STATUS_OK || res == NULL)
	{
		ERROR("Error: failed to get quote from configfs-tsm: 0x%04x\n", status);
		status = STATUS_TDX_ERROR_BASE | STATUS_QUOTE_ERROR;
		goto ERROR;
	}

	evidence->type = EVIDENCE_TYPE_TDX;
	// Populating Evidence with TDQuote
	evidence->evidence = (uint8_t *)calloc(res->out_blob_size, sizeof(uint8_t));
	if (NULL == evidence->evidence)
	{
		status = STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	memcpy(evidence->evidence, res->out_blob, res->out_blob_size);
	evidence->evidence_len = res->out_blob_size;

	// Populating Evidence with UserData
	evidence->runtime_data = (uint8_t *)calloc(user_data_len, sizeof(uint8_t));
	if (NULL == evidence->runtime_data)
	{
		free(evidence->evidence);
		evidence->evidence = NULL;
		status = STATUS_TDX_ERROR_BASE | STATUS_ALLOCATION_ERROR;
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

	response_free(res);
	return status;
}
