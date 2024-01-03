/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <connector.h>
#include <token_provider.h>
#include <log.h>

TRUST_AUTHORITY_STATUS collect_token(trust_authority_connector *connector,
		response_headers *resp_headers,
		token *token,
		policies *policies,
		const char *request_id,
		evidence_adapter *adapter,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	return collect_token_callback(connector,
			resp_headers,
			token,
			policies,
			request_id,
			adapter->collect_evidence,
			adapter->ctx,
			user_data,
			user_data_len);
}

TRUST_AUTHORITY_STATUS collect_token_callback(trust_authority_connector *connector,
		response_headers *resp_headers,
		token *token,
		policies *policies,
		const char *request_id,
		evidence_callback callback,
		void *ctx,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	int result;
	nonce nonce = {0};
	response_headers nonce_headers = {0};
	evidence evidence = {0};
	uint8_t hash[SHA512_LEN] = {0};

	if (NULL == connector)
	{
		return STATUS_NULL_CONNECTOR;
	}

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == ctx)
	{
		return STATUS_INVALID_PARAMETER;
	}

	result = get_nonce(connector, &nonce, request_id, &nonce_headers);
	if (result != STATUS_OK)
	{
		ERROR("Error: Failed to get Trust Authority nonce 0x%04x\n", result);
		goto ERROR;
	}

	//This calls sgx_collect_evidence/tdx_collect_evidence to get the quote.
	result = callback(ctx, &evidence, &nonce, user_data, user_data_len);
	if (result != STATUS_OK)
	{
		ERROR("Error: Failed to collect evidence from adapter 0x%04x\n", result);
		goto ERROR;
	}

	DEBUG("Evidence[%d] @%p", evidence.evidence_len, evidence.evidence);

	result = get_token(connector, resp_headers, token, policies, &evidence, &nonce, request_id);
	if (STATUS_OK != result)
	{
		ERROR("Error: Failed to get Trust Authority token 0x%04x\n", result);
		goto ERROR;
	}

	result = STATUS_OK;

ERROR:
	nonce_free(&nonce);
	response_headers_free(&nonce_headers);
	evidence_free(&evidence);
	return result;
}
