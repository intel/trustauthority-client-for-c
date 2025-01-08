/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TPM_ADAPTER_H__
#define __TPM_ADAPTER_H__

#include <types.h>
#include <tss2/tss2_tctildr.h> 
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    TPM_DEVICE_TYPE_UNKNOWN = 0,
    TPM_DEVICE_TYPE_LINUX = 1,
    TPM_DEVICE_TYPE_MSSIM = 2
} tpm_device_type;

#define DEFAULT_AK_HANDLE       0x81000801	// this is the default "ITA" AK handle used across clients
#define DEFAULT_PCR_SELECTION   "sha256:all"
#define DEFAULT_IMA_LOGS        "/sys/kernel/security/ima/ascii_runtime_measurements"
#define DEFAULT_UEFI_EVENT_LOGS "/sys/kernel/security/tpm0/binary_bios_measurements"
#define EVIDENCE_IDENTIFIER_TPM "tpm"

#define MIN_PERSISTENT_HANDLE	0x81000000
#define MAX_PERSISTENT_HANDLE	0x817FFFFF

#define STATUS_TPM_ERROR_BASE 0x5000

#define TPM_REPORT_DATA_SIZE 32

	/**
	 * Create a new adapter to get TPM evidence from platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int tpm_adapter_new(evidence_adapter **adapter);
 
	// Delete/free a TPM adapter.
	int tpm_adapter_free(evidence_adapter *adapter);

	/**
	 * Collects TPM evidence from platform.
	 * @param ctx a void pointer containing context
	 * @param evidence tpm evidence in the format of json_object
	 * @param nonce containing nonce
	 * @param user_data containing user data
	 * @param user_data_len containing length of user data
	 * @return int containing status
	 */
	int tpm_get_evidence(void *ctx,
			json_t *evidence,
			nonce *nonce,
			uint8_t *user_data,
			uint32_t user_data_len);

	/**
	 * @brief generates the identifier for TPM evidence
	 * 
	 * @return the resulting identifier.
	 */
	const char* tpm_get_evidence_identifier();

	/**
	 * @brief sets the owner auth password to be used by the TPM adapter
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_owner_auth(evidence_adapter *adapter, char* owner_auth);

	/**
	 * @brief sets the TPM device type to be used by the TPM adapter
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_device_type(evidence_adapter *adapter, tpm_device_type device_type);

	/**
	 * @brief sets the AK handle to be used by the TPM adapter when collecting quotes
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_ak_handle(evidence_adapter *adapter, uint32_t ak_handle);

	/**
	 * @brief sets the PCR selection to be used by the TPM adapter when collecting quotes
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_pcr_selections(evidence_adapter *adapter, TPML_PCR_SELECTION* pcr_selection);

	/**
	 * @brief determines if IMA logs will be included in TPM evidence
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_ima_log(evidence_adapter *adapter, bool flag);

	/**
	 * @brief determines if UEFI event logs will be included in TPM evidence
	 * 
	 * @return 0 on success, otherwise failure
	 */
    int tpm_with_uefi_log(evidence_adapter *adapter, bool flag);

#ifdef __cplusplus
}
#endif
#endif
