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

#define DEFAULT_AK_HANDLE       0x81000003
#define DEFAULT_PCR_SELECTION   "sha256:all"
#define DEFAULT_IMA_LOGS        "/sys/kernel/security/ima/ascii_runtime_measurements"
#define DEFAULT_UEFI_EVENT_LOGS "/sys/kernel/security/tpm0/binary_bios_measurements"
#define EVIDENCE_IDENTIFIER_TPM "tpm"

#define MIN_PERSISTENT_HANDLE	0x81000000
#define MAX_PERSISTENT_HANDLE	0x817FFFFF

#define STATUS_TPM_ERROR_BASE 0x5000

#define TPM_REPORT_DATA_SIZE 32

typedef struct tpm_adapter_context
{
	char* owner_auth;                   // Defaults to "" or set via "with_owner_auth"
	tpm_device_type device_type;        // Defaults to TPM_DEVICE_TYPE_LINUX or set via "with_device_type"
	uint32_t ak_handle;                 // Defaults to DEFAULT_AK_HANDLE or set via "with_ak_handle"
	TPML_PCR_SELECTION* pcr_selection;  // Defaults to DEFAULT_PCR_SELECTION or set via "with_pcr_selections"
	uint8_t* ima_buffer;                // Defults to empty or is included via "with_ima_logs" (contains the IMA flat file)
	size_t ima_buffer_size;             // Defaults to zero or reflects size of populated ima_buffer
	uint16_t* uefi_eventlog_buffer;     // Defaults to empty or is included via  "with_uefi_logs" (contains the raw uefi TCG data)
	size_t uefi_eventlog_buffer_size;   // Defaults to zero or reflect size of populated uefi_eventlog_buffer
	uint8_t* ak_cert_buffer;            // Defaults to empty or is set via  "with_ak_certificate_uri" (contains the AK certificate der)
	size_t ak_cert_size;                // Defaults to zero or reflects size of ak_cert_buffer
} tpm_adapter_context;


	/**
	 * Create a new adapter to get tpm quote from platform.
	 * @param adapter evidence adapter instance to initialize
	 * @return int containing status
	 */
	int tpm_adapter_new(evidence_adapter **adapter);
 
	// Delete/free a adapter.
	int tpm_adapter_free(evidence_adapter *adapter);

	/**
	 * Collect the tpm quote from platform.
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

	const char* tpm_get_evidence_identifier();

    int with_owner_auth(tpm_adapter_context *ctx, char* owner_auth);
    int with_device_type(tpm_adapter_context *ctx, tpm_device_type device_type);
    int with_ak_handle(tpm_adapter_context *ctx, uint32_t ak_handle);
    int with_pcr_selections(tpm_adapter_context *ctx, TPML_PCR_SELECTION* pcr_selection);
    int with_ima_log(tpm_adapter_context *ctx, bool flag);
    int with_uefi_log(tpm_adapter_context *ctx, bool flag);

#ifdef __cplusplus
}
#endif
#endif
