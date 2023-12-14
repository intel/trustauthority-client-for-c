/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __SGX_ADAPTER_H__
#define __SGX_ADAPTER_H__

#include <types.h>
#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define STATUS_SGX_ERROR_BASE 0x2000

	/**
	 * callback to get SGX QE Target Info
	 */
	typedef quote3_error_t (*sgx_qe_target_info_fx)(sgx_target_info_t *p_target_info);

	/**
	 * callback to get SGX Quote Size
	 */
	typedef quote3_error_t (*sgx_qe_get_quote_size_fx)(uint32_t *p_quote_size);
	/**
	 * callback to get SGX Quote
	 */
	typedef quote3_error_t (*sgx_qe_get_quote_fx)(const sgx_report_t *p_app_report, uint32_t quote_size, uint8_t *p_quote);


	/**
	 * Adapter to get quote from sgx platform.
	 */
	typedef struct sgx_adapter_context
	{
		int eid; /* integer containing enclave id */
		void *report_callback; /* function call to collect evidence */
		sgx_qe_target_info_fx sgx_qe_target_info_cb; /*function call to qe target info */
		sgx_qe_get_quote_size_fx sgx_qe_get_quote_size_cb; /*function call to get quote size*/
		sgx_qe_get_quote_fx sgx_qe_get_quote_cb; /*function call to get quote*/
	} sgx_adapter_context;

	/**
	 * callback to get SGX report from enclave
	 */
	typedef sgx_status_t (*report_fx)(sgx_enclave_id_t eid,
			uint32_t *retval,
			const sgx_target_info_t *p_qe3_target,
			uint8_t *nonce,
			uint32_t nonce_size,
			sgx_report_t *p_report);


	/**
	 * Create a new adapter to get Quote from sgx platform.
	 * @param adapter to evidence 
	 * @param int containing enclave id
	 * @param void pointer containing report function
	 * @return int containing status
	 */
	int sgx_adapter_new(evidence_adapter **adapter, 
			int eid,
			void *report_function);

	// Delete/free a adapter.
	int sgx_adapter_free(evidence_adapter *adapter);

	/**
	 * Collect the sgx quote from platform.
	 * @param ctx a void pointer containing context
	 * @param evidence quote
	 * @param nonce containing nonce recieved from Intel Trust Authority
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int sgx_collect_evidence(void *ctx,
			evidence *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

#ifdef __cplusplus
}
#endif
#endif
