/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sevsnp_adapter.h>
#include <types.h>
#include <openssl/evp.h>
#include <log.h>
#include <json.h>
#include <report.h>

/**
 * callback to get SEVSNP report
 */
typedef TRUST_AUTHORITY_STATUS (*sevsnp_get_report_fx)(Request *req, Response **res);

int sevsnp_adapter_new(evidence_adapter **adapter)
{
	sevsnp_adapter_context *ctx = NULL;
	if (NULL == adapter)
	{
		return STATUS_SEVSNP_ERROR_BASE | STATUS_NULL_ADAPTER;
	}

	*adapter = (evidence_adapter *)malloc(sizeof(evidence_adapter));
	if (NULL == *adapter)
	{
		return STATUS_SEVSNP_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx = (sevsnp_adapter_context *)calloc(1, sizeof(sevsnp_adapter_context));
	if (NULL == ctx)
	{
		free(*adapter);
		*adapter = NULL;
		return STATUS_SEVSNP_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}
	ctx->sevsnp_att_get_report_cb = get_report;
	ctx->priv_level = 0;

	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = sevsnp_collect_evidence;
	(*adapter)->get_evidence = sevsnp_get_evidence;
	(*adapter)->get_evidence_identifier = sevsnp_get_evidence_identifier;

	return STATUS_OK;
}

int sevsnp_adapter_free(evidence_adapter *adapter)
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

const char *sevsnp_get_evidence_identifier()
{
	return EVIDENCE_IDENTIFIER_SEVSNP;
}

int sevsnp_get_evidence(void *ctx,
		json_t *jansson_evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	int result = 0;
	evidence evidence = {0};
	json_t *jansson_nonce = NULL;

	result = sevsnp_collect_evidence(ctx, &evidence, nonce, user_data, user_data_len);
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

	if (nonce != NULL)
	{
		result = get_jansson_nonce(nonce, &jansson_nonce);
		if (result != STATUS_OK)
		{
			ERROR("Error: Failed to create nonce json: 0x%04x\n", result);
			goto ERROR;
		}

		if (0 != json_object_set(jansson_evidence, "verifier_nonce", jansson_nonce))
		{
			ERROR("Error: Failed to add nonce json to the evidence payload\n");
			result = STATUS_SEVSNP_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
			goto ERROR;
		}
	}

ERROR:
	if (jansson_nonce)
	{
		json_decref(jansson_nonce);
		jansson_nonce = NULL;
	}
	return result;
}

int sevsnp_collect_evidence(void *ctx,
		evidence *evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	sevsnp_adapter_context *sevsnp_ctx = NULL;
	if (NULL == ctx)
	{
		return STATUS_SEVSNP_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
	}

	if (NULL == evidence)
	{
		return STATUS_SEVSNP_ERROR_BASE | STATUS_NULL_EVIDENCE;
	}

	if (user_data_len > 0 && user_data == NULL)
	{
		return STATUS_SEVSNP_ERROR_BASE | STATUS_INVALID_USER_DATA;
	}

	sevsnp_ctx = (sevsnp_adapter_context *)ctx;
	uint32_t nonce_data_len = 0;
	uint8_t *nonce_data = NULL;

	if (NULL != nonce)
	{
		if (nonce->val == NULL)
		{
			return STATUS_SEVSNP_ERROR_BASE | STATUS_NULL_NONCE;
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
	if (NULL == mdctx)
	{
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_INVOCATION_ERROR;
		goto ERROR;
	}
	if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
	{
		EVP_MD_CTX_free(mdctx);
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_INVOCATION_ERROR;
		goto ERROR;
	}
	if (1 != EVP_DigestUpdate(mdctx, nonce_data, nonce_data_len))
	{
		EVP_MD_CTX_free(mdctx);
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_INVOCATION_ERROR;
		goto ERROR;
	}
	if (1 != EVP_DigestUpdate(mdctx, user_data, user_data_len))
	{
		EVP_MD_CTX_free(mdctx);
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_INVOCATION_ERROR;
		goto ERROR;
	}
	if (1 != EVP_DigestFinal_ex(mdctx, md_value, &md_len))
	{
		EVP_MD_CTX_free(mdctx);
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_INVOCATION_ERROR;
		goto ERROR;
	}
	EVP_MD_CTX_free(mdctx);

	Request req = {
		.priv_level = sevsnp_ctx->priv_level,
		.in_blob = md_value,
		.in_blob_size = SEVSNP_REPORT_DATA_SIZE,
		.get_aux_blob = 0};

	if (sevsnp_ctx->sevsnp_att_get_report_cb == NULL)
	{
		ERROR("Error: callback function is empty");
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_NULL_CALLBACK;
		goto ERROR;
	}

	Response *res = NULL;
	status = ((sevsnp_get_report_fx)sevsnp_ctx->sevsnp_att_get_report_cb)(&req, &res);
	if (status != STATUS_OK || res == NULL)
	{
		ERROR("failed to get report from configfs-tsm.\n");
		status = STATUS_QUOTE_ERROR;
		goto ERROR;
	}

	evidence->type = EVIDENCE_TYPE_SEVSNP;
	// Populating Evidence with report data
	evidence->evidence = (uint8_t *)calloc(res->out_blob_size, sizeof(uint8_t));
	if (NULL == evidence->evidence)
	{
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_ALLOCATION_ERROR;
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
		status = STATUS_SEVSNP_ERROR_BASE | STATUS_ALLOCATION_ERROR;
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
