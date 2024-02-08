/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TOKEN_PROVIDER_H__
#define __TOKEN_PROVIDER_H__

#include <connector.h>

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Utility function that gets nonce, evidence (provided by evidence_adapter) and gets a token from Intel Trust Authority SaaS.
	 * @param connector connector instance to connect to Intel Trust Authority
	 * @param resp_headers char pointer containing response headers returned from Intel Trust Authority
	 * @param token token returned from Intel Trust Authority
	 * @param policies policy cretaed in Intel Trust Authority
	 * @param request_id id to uniquely identify the request
	 * @param adapter sgx/tdx adapter
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return return status
	 */
	TRUST_AUTHORITY_STATUS collect_token(trust_authority_connector *connector,
			response_headers *resp_headers,
			token *token,
			policies *policies,
			const char *request_id,
			evidence_adapter *adapter,
			uint8_t *user_data,
			uint32_t user_data_len);

	/**
	 * Utility call back function that gets nonce, evidence (provided by evidence_adapter) and gets a token from Intel Trust Authority SaaS.
	 * @param connector connector instance to connect to Intel Trust Authority
	 * @param response_headers a char pointer containing response headers returned from Intel Trust Authority
	 * @param token token returned from Intel Trust Authority
	 * @param policies policy cretaed in Intel Trust Authority
	 * @param request_id id to uniquely identify the request
	 * @param callback to sgx/tdx adapter to get evidence
	 * @param ctx context containing context details
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return return status
	 */
	TRUST_AUTHORITY_STATUS collect_token_callback(trust_authority_connector *connector,
			response_headers *resp_headers,
			token *token,
			policies *policies,
			const char *request_id,
			evidence_callback callback,
			void *ctx,
			uint8_t *user_data,
			uint32_t user_data_len);

	/**
	 * Utility function that gets nonce, evidence (provided by evidence_adapter) and gets a token from Intel Trust Authority SaaS for AZURE platform.
	 * @param connector connector instance to connect to Intel Trust Authority
	 * @param resp_headers char pointer containing response headers returned from Intel Trust Authority
	 * @param token token returned from Intel Trust Authority
	 * @param policies policy cretaed in Intel Trust Authority
	 * @param request_id id to uniquely identify the request
	 * @param adapter sgx/tdx adapter
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return return status
	 */
	TRUST_AUTHORITY_STATUS collect_token_azure(trust_authority_connector *connector,
			response_headers *resp_headers,
			token *token,
			policies *policies,
			const char *request_id,
			evidence_adapter *adapter,
			uint8_t *user_data,
			uint32_t user_data_len);

#ifdef __cplusplus
}
#endif
#endif
