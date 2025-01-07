/*
 * Copyright (C) 2023-2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TDX_ADAPTER_H__
#define __TDX_ADAPTER_H__

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EVIDENCE_IDENTIFIER_TDX "tdx"
#define STATUS_TDX_ERROR_BASE 0x3000
#define TD_REPORT_OFFSET 32
#define TD_REPORT_SIZE 1024
#define RUNTIME_DATA_SIZE_OFFSET 1232
#define RUNTIME_DATA_OFFSET 1236
#define REPORT_DATA_NVINDEX 0x01400002
#define TD_REPORT_NVINDEX 0x01400001
#define TDX_REPORT_DATA_SIZE 64

	/**
	 * Adapter to get quote from tdx platform.
	 */
	typedef struct tdx_adapter_context
	{
		void* tdx_att_get_quote_cb; /*function call to get quote*/
	} tdx_adapter_context;

	/**
	 * Create a new adapter to get Quote from tdx platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int tdx_adapter_new(evidence_adapter **adapter);

	/**
	 * Create a new adapter to get Quote from Azure tdx platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int azure_tdx_adapter_new(evidence_adapter **adapter);
 
	// Delete/free an adapter.
	int tdx_adapter_free(evidence_adapter *adapter);

	/**
	 * Collect the tdx quote from platform.
	 * @param ctx a void pointer containing context
	 * @param evidence quote
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 *  @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int tdx_collect_evidence(void *ctx,
			evidence *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

	int tdx_collect_evidence_azure(void *ctx,
			evidence *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

	int tdx_get_evidence(void *ctx,
			json_t *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

	int tdx_get_evidence_azure(void *ctx,
			json_t *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

	const char* tdx_get_evidence_identifier();

#ifdef __cplusplus
}
#endif

#endif // __TDX_ADAPTER_H__
