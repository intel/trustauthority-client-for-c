/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TDX_ADAPTER_H__
#define __TDX_ADAPTER_H__

#include <types.h>
#include <tdx_attest.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define STATUS_TDX_ERROR_BASE 0x3000

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

	typedef struct tdx_adapter_context
	{
		tdx_get_quote_fx tdx_att_get_quote_cb;
	} tdx_adapter_context;

	/**
	 * Create a new adapter to get Quote from tdx platform.
	 * @param adapter to evidence 
	 * @return int containing status
	 */
	int tdx_adapter_new(evidence_adapter **adapter);
 
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

#ifdef __cplusplus
}
#endif
#endif
