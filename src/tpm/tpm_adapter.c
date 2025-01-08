/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <tpm_adapter.h>
#include <openssl/evp.h>
#include <jansson.h>
#include <rest.h>
#include <json.h>
#include <base64.h>
#include <log.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h> 
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <curl/curl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>

#define MAX_BUF_SIZE 1024 * 1024 // 1MB buffer
#define CHUNK_SIZE 512

typedef struct tpm_adapter_context
{
	char* owner_auth;                   // Defaults to "" or set via "tpm_with_owner_auth"
	tpm_device_type device_type;        // Defaults to TPM_DEVICE_TYPE_LINUX or set via "tpm_with_device_type"
	uint32_t ak_handle;                 // Defaults to DEFAULT_AK_HANDLE or set via "tpm_with_ak_handle"
	TPML_PCR_SELECTION* pcr_selection;  // Defaults to DEFAULT_PCR_SELECTION or set via "tpm_with_pcr_selections"
	bool with_ima_log;					// When true, includes ima evidence from /sys/kernel/security/ima/ascii_runtime_measurements
	bool with_uefi_log;					// When true, includes uefi evidence from /sys/kernel/security/tpm0/binary_bios_measurements
} tpm_adapter_context;

TPML_PCR_SELECTION DEFAULT_TPML_PCR_SELECTION = {
    .count = 1,                             // Only one bank (SHA-256)
    .pcrSelections = {
        {
            .hash = TPM2_ALG_SHA256,        // SHA-256 algorithm
            .sizeofSelect = 3,              // 3 bytes for PCR selection (covering 24 PCRs)
            .pcrSelect = {0xFF, 0xFF, 0xFF} // Lower 24 bits set: PCRs 0-23
        }
    }
};

int get_quote(ESYS_CONTEXT *ctx, 
                uint32_t ak_handle, 
                TPML_PCR_SELECTION *pcr_selection, 
                TPM2B_DATA *qualifying_data, 
                uint8_t **quote_buffer,
                size_t *quote_buffer_size,
                uint8_t **signature_buffer,
                size_t *signature_buffer_size);

int get_pcrs(ESYS_CONTEXT *ctx, 
                TPML_PCR_SELECTION *pcr_selection, 
                uint8_t **flattened_pcrs,
                size_t *flattened_pcrs_len);

TRUST_AUTHORITY_STATUS read_sysfile_base64(const char* path, uint8_t** base64_buffer, size_t* buffer_len);

int tpm_adapter_new(evidence_adapter **adapter)
{
	tpm_adapter_context *ctx = NULL;
	if (NULL == adapter)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
	}

	*adapter = (evidence_adapter *)malloc(sizeof(evidence_adapter));
	if (NULL == *adapter)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx = (tpm_adapter_context *)calloc(1, sizeof(tpm_adapter_context));
	if (NULL == ctx)
	{
		free(*adapter);
		*adapter = NULL;
		return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx->owner_auth = "";
	ctx->device_type = TPM_DEVICE_TYPE_LINUX;
	ctx->ak_handle = DEFAULT_AK_HANDLE;
	ctx->pcr_selection = &DEFAULT_TPML_PCR_SELECTION;

	(*adapter)->ctx = ctx;
	(*adapter)->collect_evidence = NULL;
	(*adapter)->get_evidence = tpm_get_evidence;
	(*adapter)->get_evidence_identifier = tpm_get_evidence_identifier;

	return STATUS_OK;
}

int tpm_adapter_free(evidence_adapter *adapter)
{
	if (NULL != adapter)
	{
		if (NULL != adapter->ctx)
		{
			free(adapter->ctx);
			adapter->ctx = NULL;
		}

		free(adapter);
		adapter = NULL;
	}

	return STATUS_OK;
}

const char* tpm_get_evidence_identifier() {
	return EVIDENCE_IDENTIFIER_TPM;
}

int tpm_with_owner_auth(evidence_adapter *adapter, char* owner_auth)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }

    if (NULL == owner_auth)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    if (strlen(owner_auth) == 0 || strlen(owner_auth) > sizeof(TPMU_HA)) // need double check
    {
        return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context*)adapter->ctx;
    ctx->owner_auth = owner_auth;
    return STATUS_OK;
}

int tpm_with_device_type(evidence_adapter *adapter, tpm_device_type device_type)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }

    if (device_type != TPM_DEVICE_TYPE_LINUX || device_type != TPM_DEVICE_TYPE_MSSIM)
    {
        return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context*)adapter->ctx;
    ctx->device_type = device_type;
    return STATUS_OK;
}

int tpm_with_ak_handle(evidence_adapter *adapter, uint32_t ak_handle)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }

    if (ak_handle < MIN_PERSISTENT_HANDLE || ak_handle > MAX_PERSISTENT_HANDLE)
    {
        return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context*)adapter->ctx;
    ctx->ak_handle = ak_handle;
    return STATUS_OK;
}

int tpm_with_pcr_selections(evidence_adapter *adapter, TPML_PCR_SELECTION* pcr_selection)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }
    
    if (NULL == pcr_selection)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context*)adapter->ctx;
    ctx->pcr_selection = pcr_selection;
    return STATUS_OK;
}

int tpm_with_ima_log(evidence_adapter *adapter, bool flag)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context *)adapter->ctx;
    ctx->with_ima_log = flag;
    return STATUS_OK;
}

int tpm_with_uefi_log(evidence_adapter *adapter, bool flag)
{
    if (NULL == adapter)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER;
    }

    if(NULL == adapter->ctx)
    {
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
    }

    tpm_adapter_context *ctx = (tpm_adapter_context *)adapter->ctx;
    ctx->with_uefi_log = flag;
    return STATUS_OK;
}

int tpm_get_evidence(void *ctx,
		json_t *jansson_evidence,
		nonce *nonce,
		uint8_t *user_data,
		uint32_t user_data_len)
{
	evidence evidence = {0};
	json_t *jansson_nonce = NULL;

	tpm_adapter_context *tpm_ctx = NULL;
	uint32_t nonce_data_len = 0;
	uint8_t *nonce_data = NULL;
	ESYS_CONTEXT *esys_ctx;
	TSS2_TCTI_CONTEXT *tcti = NULL;
	TPM2B_DATA qualifying_data = {0};
	uint8_t *runtime_data;
	uint32_t runtime_data_len;
	char *report_data_hex = NULL;
	json_t *runtime_data_json;
	json_t *user_data_json;
	char *user_data_string;
	int status = STATUS_OK;

	uint8_t *pcrs_buffer = NULL;
	size_t pcrs_buffer_size = 0;
	uint8_t *quote_buffer = NULL;
	size_t quote_buffer_size = 0;
	uint8_t *signature_buffer = NULL;
	size_t signature_buffer_size = 0;

	uint8_t* b64 = NULL;
	size_t output_length = 0;

	tpm_ctx = (tpm_adapter_context *)ctx;
	if (NULL == ctx)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
	}

	if (user_data_len > 0 && user_data == NULL)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_INVALID_USER_DATA;
	}

	if (NULL != nonce)
	{
		if (nonce->val == NULL)
		{
			return STATUS_TPM_ERROR_BASE | STATUS_NULL_NONCE;
		}
		// append nonce->val and nonce->iat
		nonce_data_len = nonce->val_len + nonce->iat_len;
		nonce_data = (uint8_t *)calloc(1, (nonce_data_len + 1) * sizeof(uint8_t));
		if (NULL == nonce_data)
		{
			status = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
			goto ERROR;
		}

		memcpy(nonce_data, nonce->val, nonce->val_len);
		memcpy(nonce_data + nonce->val_len, nonce->iat, nonce->iat_len);
	}

	if (nonce_data != NULL || user_data != NULL)
	{
		// Hashing Nonce and UserData
		unsigned char md_value[EVP_MAX_MD_SIZE];
		unsigned int md_len;
		const EVP_MD *md = EVP_get_digestbyname("sha256");
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, md, NULL);
		EVP_DigestUpdate(mdctx, nonce_data, nonce_data_len);
		EVP_DigestUpdate(mdctx, user_data, user_data_len);
		EVP_DigestFinal_ex(mdctx, md_value, &md_len);
		EVP_MD_CTX_free(mdctx);
		memcpy(qualifying_data.buffer, md_value, TPM_REPORT_DATA_SIZE);
		qualifying_data.size = TPM_REPORT_DATA_SIZE;
	}

	if(status = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti)!= TSS2_RC_SUCCESS) 
	{
        	ERROR("Tss2_TctiLdr_Initialize failed with error: 0x%x\n", status);
        	goto ERROR;
	}

    	if(status = Esys_Initialize(&esys_ctx, tcti, NULL) != TSS2_RC_SUCCESS) 
    	{
        	ERROR("Esys_Initialize failed with error: 0x%x\n", status);
        	goto ERROR;
    	}

	if(status = get_quote(esys_ctx, 
                        tpm_ctx->ak_handle, 
                        tpm_ctx->pcr_selection, 
                        &qualifying_data, 
                        &quote_buffer,
                        &quote_buffer_size,
                        &signature_buffer,
                        &signature_buffer_size) != TSS2_RC_SUCCESS) 
    	{
        	ERROR("get_quote failed with error: 0x%x\n", status);
        	goto ERROR;
    	}

	output_length = ((quote_buffer_size + 2) / 3) * 4 + 1;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}
	status = base64_encode(quote_buffer, quote_buffer_size, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		status = STATUS_TPM_ERROR_BASE | STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(jansson_evidence, "quote", json_string(b64));
	free(b64);
	b64 = NULL;

	output_length = ((signature_buffer_size + 2) / 3) * 4 + 1;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}
	status = base64_encode(signature_buffer, signature_buffer_size, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		status = STATUS_TPM_ERROR_BASE | STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(jansson_evidence, "signature", json_string(b64));
	free(b64);
	b64 = NULL;

	if (user_data != NULL)
	{
		output_length = ((user_data_len + 2) / 3) * 4 + 1;
		b64 = (char *)malloc(output_length * sizeof(char));
		if (b64 == NULL)
		{
			return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
		}
		status = base64_encode(user_data, user_data_len, b64, output_length, false);
		if (BASE64_SUCCESS != status)
		{
			status = STATUS_TPM_ERROR_BASE | STATUS_JSON_ENCODING_ERROR;
			goto ERROR;
		}

		json_object_set(jansson_evidence, "user_data", json_string(b64));

		free(b64);
		b64 = NULL;
	}

	//
    	// get PCRs and add to evidence
    	//
    	if(status = get_pcrs(esys_ctx, 
                    tpm_ctx->pcr_selection, 
                    &pcrs_buffer,
                    &pcrs_buffer_size) != STATUS_OK) 
    	{
        	ERROR("get_pcrs failed with error: 0x%x\n", status);
        	goto ERROR;
    	}

	output_length = ((pcrs_buffer_size + 2) / 3) * 4 + 1;
	b64 = (char *)malloc(output_length * sizeof(char));
	if (b64 == NULL)
	{
		return STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}
	status = base64_encode(pcrs_buffer, pcrs_buffer_size, b64, output_length, false);
	if (BASE64_SUCCESS != status)
	{
		status = STATUS_TPM_ERROR_BASE | STATUS_JSON_ENCODING_ERROR;
		goto ERROR;
	}

	json_object_set(jansson_evidence, "pcrs", json_string(b64));
	free(b64);
	b64 = NULL;

	if(tpm_ctx->with_ima_log)
    {
        status = read_sysfile_base64(DEFAULT_IMA_LOGS, &b64, &output_length);
		if (STATUS_OK != status)
		{
            ERROR("Failed to read ima logs\n");
			goto ERROR;
		}

        json_object_set(jansson_evidence, "ima_logs", json_string(b64));
        free(b64);
		b64 = NULL;
    }

    if(tpm_ctx->with_uefi_log)
    {
        status = read_sysfile_base64(DEFAULT_UEFI_EVENT_LOGS, &b64, &output_length);
		if (STATUS_OK != status)
		{
            ERROR("Failed to read uefi event logs\n");
            goto ERROR;
		}

        json_object_set(jansson_evidence, "uefi_event_logs", json_string(b64));
        free(b64);
		b64 = NULL;
    }

	if (nonce != NULL) {
		status = get_jansson_nonce(nonce, &jansson_nonce);
		if (STATUS_OK != status)
		{
			ERROR("Error: Failed to create nonce json: 0x%04x\n", status);
			goto ERROR;
		}

		json_object_set(jansson_evidence, "verifier_nonce", jansson_nonce);
	}

ERROR:
	if (nonce_data)
	{
		free(nonce_data);
		nonce_data = NULL;
	}
	if (jansson_nonce)
	{
		json_decref(jansson_nonce);
		jansson_nonce = NULL;
	}
	if(tcti != NULL)
    	{
        	Tss2_TctiLdr_Finalize(&tcti);
    	}
    	if(ctx != NULL)
    	{
        	Esys_Finalize(&esys_ctx);
    	}
    	if(quote_buffer != NULL)
    	{
        	free(quote_buffer);
    	}
    	if(signature_buffer != NULL)
    	{
        	free(signature_buffer);
    	}
    	if(pcrs_buffer != NULL)
    	{
        	free(pcrs_buffer);
    	}
    	if(b64 != NULL)
    	{
        	free(b64);
    	}

	return status;
}

int get_quote(ESYS_CONTEXT *ctx, 
    uint32_t ak_handle, 
    TPML_PCR_SELECTION *pcr_selection, 
    TPM2B_DATA *qualifying_data, 
    uint8_t **quote_buffer,
    size_t *quote_buffer_size,
    uint8_t **signature_buffer,
    size_t *signature_buffer_size)
{
    uint32_t rc = STATUS_OK;
    ESYS_TR ak;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    size_t mu_buffer_size = 1024;
    TPMT_SIG_SCHEME in_scheme = {0};
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qualified_name = NULL;

    if(rc = Esys_TR_FromTPMPublic(ctx, 
                                    ak_handle, 
                                    ESYS_TR_NONE, 
                                    ESYS_TR_NONE, 
                                    ESYS_TR_NONE, 
                                    &ak) != TSS2_RC_SUCCESS) 
    {
        ERROR("Esys_TR_FromTPMPublic failed with error: 0x%x\n", rc);
        return rc;
    }

    //
    // Read the public key of the AK to determine the scheme to use
    // when getting the quote (Azure uses rssa and pTPMs configured
    // by the go-client use rsapss).
    //
    if(rc =  rc = Esys_ReadPublic(ctx,
                                    ak,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    &out_public,
                                    &name,
                                    &qualified_name) != TSS2_RC_SUCCESS) 
    {
        ERROR("Esys_ReadPublic failed with error: 0x%x\n", rc);
        goto DONE;
    }

    if (out_public->publicArea.parameters.rsaDetail.scheme.scheme != TPM2_ALG_NULL) 
    {
        in_scheme.scheme = out_public->publicArea.parameters.rsaDetail.scheme.scheme;
        in_scheme.details.rsassa.hashAlg = out_public->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg;
        in_scheme.details.rsapss.hashAlg = out_public->publicArea.parameters.rsaDetail.scheme.details.rsapss.hashAlg;
    } else {
        ERROR("Unsupported AK scheme 0x%x at handle 0x%x\n", out_public->publicArea.parameters.rsaDetail.scheme.scheme, ak_handle);
        goto DONE;
    }

    if(rc = Esys_Quote(ctx,
                        ak,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        qualifying_data,
                        &in_scheme,
                        pcr_selection, 
                        &quoted,
                        &signature) != TSS2_RC_SUCCESS) 
    {
        ERROR("Esys_Quote failed with error: 0x%x\n", rc);
        goto DONE;
    }

    *quote_buffer_size = quoted->size;
    *quote_buffer = malloc(quoted->size);
    if(*quote_buffer == NULL)
    {
        ERROR("Failed to allocate memory for quote_buffer\n");
        rc = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }
    memcpy(*quote_buffer, quoted->attestationData, quoted->size);

    // buffer for mashalling tss2 structures
    *signature_buffer = calloc(1, mu_buffer_size);
    if(signature_buffer == NULL)
    {
        ERROR("Failed to allocate memory for mu_buffer\n");
        rc = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }

    if(rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, *signature_buffer, mu_buffer_size, signature_buffer_size) != TSS2_RC_SUCCESS) 
    {
        printf("Failed to marshal TPM2B_ATTEST: 0x%x\n", rc);
        goto DONE;
    }

DONE:
    if(quoted != NULL)
    {
        free(quoted);
        quoted = NULL;
    }

    if(signature != NULL)
    {
        free(signature);
        signature = NULL;
    }

    if (out_public != NULL)
    {
        free(out_public);
        out_public = NULL;
    }

    if (name != NULL)
    {
        free(name);
        name = NULL;
    }

    if(qualified_name != NULL)
    {
        free(qualified_name);
        qualified_name = NULL;
    }
        

    return rc;
}

// get_pcrs reads the PCRs from the TPM based on the 'pcr_selection'.  It aggregates
// the results into a 'flat' buffer of concatenated PCR digests as expected by the 
// ITA cluster (and similar to 'tpm2_pcrread --pcrs_format=values').
int get_pcrs(ESYS_CONTEXT *ctx, 
    TPML_PCR_SELECTION *pcr_selection, 
    uint8_t **flattened_pcrs,
    size_t *flattened_pcrs_len)
{
    uint32_t rc = STATUS_OK;
    uint32_t pcr_update_counter = 0;
    TPML_PCR_SELECTION *pcr_selection_out = NULL;
    TPML_PCR_SELECTION *pcr_selection_chunk = NULL;
    size_t pcr_len = 0;
    uint32_t pcr_mask = 0;
    size_t offset = 0;

    pcr_selection_chunk = (TPML_PCR_SELECTION*)malloc(sizeof(TPML_PCR_SELECTION));
    if (pcr_selection_chunk == NULL)
    {
        ERROR("Failed to allocate memory for pcr_selection_chunk\n");
        rc = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }

    // first calculate the total length based on the input pcr selection
    for (int i = 0; i < pcr_selection->count; i++)
    {
        pcr_len = 0;
        switch (pcr_selection->pcrSelections[i].hash)
        {
        case TPM2_ALG_SHA1:
            pcr_len = 20;
            break;
        case TPM2_ALG_SHA256:
            pcr_len = 32;
            break;
        case TPM2_ALG_SHA384:
            pcr_len = 48;
            break;
        case TPM2_ALG_SHA512:
            pcr_len = 64;
            break;
        default:
            ERROR("Unknown pcr selection hash: 0x%x", pcr_selection->pcrSelections[i].hash);
            rc = STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
            goto DONE;
        }

        // pcr selection is a 4 byte bit map
        pcr_mask = 0;
        memcpy(&pcr_mask, pcr_selection->pcrSelections[i].pcrSelect, pcr_selection->pcrSelections[i].sizeofSelect);

        for (int j = 0; j < 32; j++)
        {
            int mask = 1 << j;
            if ((pcr_mask & mask) == mask)
            {
                *flattened_pcrs_len += pcr_len;
            }
        }
    }

    *flattened_pcrs = (uint8_t*)calloc(1, *flattened_pcrs_len);
    if (*flattened_pcrs == NULL)
    {
        ERROR("Failed to allocate memory for flattened_pcrs\n");
        rc = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }

    // PCRs must be read across multiple requests to the TPM.  Iterate
    // over the pcr selection, reading each chunk one at a time.
    for(int i = 0; i < pcr_selection->count; i++)
    {
        for(int j = 0; j < pcr_selection->pcrSelections[i].sizeofSelect; j++)
        {
            if(pcr_selection->pcrSelections[i].sizeofSelect != 0)
            {
                // copy the single PCR selection into the "chunk" selection
                memset(pcr_selection_chunk, 0, sizeof(TPML_PCR_SELECTION));
                pcr_selection_chunk->count = 1;
                pcr_selection_chunk->pcrSelections[0].hash = pcr_selection->pcrSelections[i].hash;
                pcr_selection_chunk->pcrSelections[0].sizeofSelect = 3;
                pcr_selection_chunk->pcrSelections[0].pcrSelect[j] = pcr_selection->pcrSelections[i].pcrSelect[j];

                TPML_DIGEST *pcr_values = NULL;
                if(rc = Esys_PCR_Read(ctx,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                pcr_selection_chunk,
                                &pcr_update_counter,
                                &pcr_selection_out,
                                &pcr_values) != TSS2_RC_SUCCESS) 
                {
                    ERROR("Esys_PCR_Read failed with error: 0x%x\n", rc);
                    goto DONE;
                }

                for (int k = 0; k < pcr_values->count; k++)
                {
                    memcpy(*flattened_pcrs + offset, pcr_values->digests[k].buffer, pcr_values->digests[k].size);
                    offset += pcr_values->digests[k].size;
                }

                free(pcr_values);
            }
        }
    }

DONE:
    if(pcr_selection_out != NULL)
    {
        free(pcr_selection_out);
        pcr_selection_out = NULL;
    }

    if(pcr_selection_chunk != NULL)
    {
        free(pcr_selection_chunk);
        pcr_selection_chunk = NULL;
    }

    if (rc != STATUS_OK)
    {
        if (*flattened_pcrs != NULL)
        {
            free(*flattened_pcrs);
            *flattened_pcrs = NULL;
        }

        *flattened_pcrs_len = 0;
    }

    return rc;
}

// Reads a "/sys" file specified by 'file_path' and allocates a buffer
// containing its base64 encoded contents.  Handles the fact that /sys
// files do not report their length via "ftell".  Callers must free the
// allocated buffer when done.
TRUST_AUTHORITY_STATUS read_sysfile_base64(const char* file_path, uint8_t** base64_buffer, size_t* base64_buffer_len)
{
    TRUST_AUTHORITY_STATUS status = STATUS_OK;
    FILE *file = NULL;
    uint8_t *file_buffer = NULL;
    int bytes_read = 0;

    if(NULL == file_path || NULL == base64_buffer || NULL == base64_buffer_len)
    {
        return STATUS_TPM_ERROR_BASE | STATUS_INVALID_PARAMETER;
    }

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        return STATUS_TPM_ERROR_BASE | STATUS_FILE_OPEN_ERROR;
    }

    file_buffer = calloc(MAX_BUF_SIZE, sizeof(uint8_t));
    if (file_buffer == NULL) 
    {
        status = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }

    while(bytes_read < MAX_BUF_SIZE)
    {
        int r = fread(file_buffer + bytes_read, 1, CHUNK_SIZE, file);
        if (r < 0)
        {
            status = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
            goto DONE;
        } 

        bytes_read += r;

        // end of file
        if (r < CHUNK_SIZE)
        {
            break;
        }           
    }

    DEBUG("Successfully read %d bytes from file %s\n", bytes_read, file_path);

	*base64_buffer_len = ((bytes_read + 2) / 3) * 4 + 1;
    *base64_buffer = malloc(*base64_buffer_len * sizeof(uint8_t));
    if (*base64_buffer == NULL)
    {
        *base64_buffer_len = 0;
        status = STATUS_TPM_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        goto DONE;
    }

    status = base64_encode(file_buffer, bytes_read, *base64_buffer, base64_buffer_len, false);
    if (status != BASE64_SUCCESS)
    {
        ERROR("Failed to base64 encode file contents of %s\n", file_path);
        *base64_buffer_len = 0;
        free(*base64_buffer);
        *base64_buffer = NULL;
        status = STATUS_TPM_ERROR_BASE | STATUS_JSON_ENCODING_ERROR;
        goto DONE;
    }

DONE:

    if (file)
    {
        fclose(file);
    }

    if(file_buffer)
    {
        free(file_buffer);
    }   

    return status;
}