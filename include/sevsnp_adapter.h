/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __SEVSNP_ADAPTER_H__
#define __SEVSNP_ADAPTER_H__

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EVIDENCE_IDENTIFIER_SEVSNP "sevsnp"
#define STATUS_SEVSNP_ERROR_BASE 0x4000
#define SEVSNP_REPORT_OFFSET 32
#define SEVSNP_REPORT_SIZE 1184
#define RUNTIME_DATA_SIZE_OFFSET 1232
#define RUNTIME_DATA_OFFSET 1236
#define REPORT_DATA_NVINDEX 0x01400002
#define SEVSNP_REPORT_NVINDEX 0x01400001
#define SEVSNP_REPORT_DATA_SIZE 64

	typedef struct sevsnp_adapter_context
	{
		void *sevsnp_att_get_report_cb;
		unsigned int priv_level;
	} sevsnp_adapter_context;

	/**
	 * Create a new adapter to get Report from sevsnp platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int sevsnp_adapter_new(evidence_adapter **adapter);

	/**
	 * Create a new adapter to get Report from Azure sevsnp platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int azure_sevsnp_adapter_new(evidence_adapter **adapter);

	// Delete/free a adapter.
	int sevsnp_adapter_free(evidence_adapter *adapter);

	/**
	 * Collect the sevsnp report from on-prem/GCP platform.
	 * @param ctx a void pointer containing context
	 * @param evidence report
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int sevsnp_collect_evidence(void *ctx,
								evidence *evidence,
								nonce *nonce,
								uint8_t *user_data,
								uint32_t user_data_len);

	/**
	 * Collect the sevsnp report from Azure platform.
	 * @param ctx a void pointer containing context
	 * @param evidence report
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int sevsnp_collect_evidence_azure(void *ctx,
									  evidence *evidence,
									  nonce *nonce,
									  uint8_t *user_data,
									  uint32_t user_data_len);

	/**
	 * Collect the sevsnp report from on-prem/GCP platform.
	 * @param ctx a void pointer containing context
	 * @param evidence report wrapped as json_object
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int sevsnp_get_evidence(void *ctx,
							json_t *evidence,
							nonce *nonce,
							uint8_t *user_data,
							uint32_t user_data_len);

	/**
	 * Collect the sevsnp report from Azure platform.
	 * @param ctx a void pointer containing context
	 * @param evidence report wrapped as json_object
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int sevsnp_get_evidence_azure(void *ctx,
								  json_t *evidence,
								  nonce *nonce,
								  uint8_t *user_data,
								  uint32_t user_data_len);

	const char *sevsnp_get_evidence_identifier();

#ifdef __cplusplus
}
#endif
#endif