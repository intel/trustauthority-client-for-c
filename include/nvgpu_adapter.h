/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __NVGPU_ADAPTER_H__
#define __NVGPU_ADAPTER_H__

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EVIDENCE_IDENTIFIER_NVGPU "nvgpu"
#define STATUS_NVGPU_ERROR_BASE 0x8000

	/**
	 * Adapter context to get evidence and corresponding certs chain from NVIDIA GPU on platform.
	 */
	typedef struct nvgpu_adapter_context
	{
		// Placeholder for any context data needed by the adapter
	} nvgpu_adapter_context;

	/**
	 * @brief 
	 * Create a new adapter to get evidence and corresponding certs chain from NVIDIA GPU provisioned.
	 * @param adapter pointer reference to evidence adapter 
	 * @return int containing status
	 */
	int nvgpu_adapter_new(evidence_adapter **adapter);

	// Delete/free a adapter.
	int nvgpu_adapter_free(evidence_adapter *adapter);

	/**
	 * @brief 
	 * Collect NVGPU evidence from NVIDIA GPU and generate JSON object based request body for ITA attestation.
	 * @param ctx the pointer of context
	 * @param evidence the pointer reference of generated JSON object based evidence
	 * @param nonce the pointer of nonce
	 * @param user_data should be NULL as it is not supported by NVGPU attestation
	 * @param user_data_len should be 0 as it is not supported by NVGPU attestation
	 * @return size_t 
	 */
	int nvgpu_get_evidence(void *ctx,
			json_t *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);
	
	/**
	 * @brief generate the identifier for the NVGPU evidence
	 * 
	 * @return the resulting identifier.
	 */
	const char* nvgpu_get_evidence_identifier();

#ifdef __cplusplus
}
#endif
#endif
