/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TDX_ADAPTER_H__
#define __TDX_ADAPTER_H__

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define STATUS_TDX_ERROR_BASE 0x3000
#define STATUS_AMD_ERROR_BASE 0x3100
#define TDX_TD_REPORT_OFFSET 32
#define AMD_TD_REPORT_OFFSET 32
#define TDX_TD_REPORT_SIZE 1024
#define AMD_TD_REPORT_SIZE 1184
#define RUNTIME_DATA_SIZE_OFFSET 1232
#define RUNTIME_DATA_OFFSET 1236
#define REPORT_DATA_NVINDEX 0x01400002
#define TD_REPORT_NVINDEX 0x01400001
#define TDX_REPORT_DATA_SIZE 64
#define AMD_REPORT_DATA_SIZE 64

	//TDX
	typedef struct tdx_adapter_context
	{
		void* tdx_att_get_quote_cb;
	} tdx_adapter_context;

	/**
	 * Create a new adapter to get Quote from tdx platform.
	 * @param adapter to evidence 
	 * @return int containing status
	 */
	int tdx_adapter_new(evidence_adapter **adapter);

	/**
	 * Create a new adapter to get Quote from Azure tdx platform.
	 * @param adapter to evidence
	 * @return int containing status
	 */
	int azure_tdx_adapter_new(evidence_adapter **adapter);
 
	// Delete/free a adapter.
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

	//AMD for Azure only
	typedef struct amd_adapter_context
	{
		void* amd_att_get_quote_cb;
	} amd_adapter_context;

	/**
	 * Create a new adapter to get Quote from Azure amd platform.
	 * @param adapter to evidence
	 * @return int containing status
	 */
	int azure_amd_adapter_new(evidence_adapter **adapter);
 
	// Delete/free a adapter.
	int amd_adapter_free(evidence_adapter *adapter);

	/**
	 * Collect the tdx quote from platform.
	 * @param ctx a void pointer containing context
	 * @param evidence quote
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 *  @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int amd_collect_evidence_azure(void *ctx,
			evidence *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);


#ifdef __cplusplus
}
#endif
#endif
