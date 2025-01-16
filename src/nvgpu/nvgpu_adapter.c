/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <assert.h>
#include <json.h>
#include <log.h>
#include <nvgpu_adapter.h>
#include <nvml.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

/**
 * Collect the NVIDIA GPU evidence & certchain from platform.
 * @param ctx a void pointer containing context
 * @param evidence GPU evidence & certchain
 * @param nonce containing nonce recieved from Intel Trust Authority
 * @param certchain containing certificate chain as output
 * @param certchain_len containing length of certificate chain
 * @param gpu_nonce containing GPU nonce as output
 * @param gpu_nonce_len containing length of GPU nonce
 * @return int containing status
 */
int nvgpu_collect_evidence (void *ctx, evidence *evidence, nonce *nonce, uint8_t **certchain, uint32_t *certchain_len, uint8_t **gpu_nonce,
                            uint32_t *gpu_nonce_len, uint8_t *user_data, uint32_t user_data_len);

/**
 * @brief
 * Extract and convert GPU nonce to hex string.
 * @param nvgpu_nonce the pointer of GPU nonce
 * @param nvgpu_nonce_len the size of GPU nonce
 * @param buf_nonce the pointer of buffer to store hex string
 * @param buf_sz the size of buffer
 * @return size_t
 */
size_t extract_nvgpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, char *buf_nonce, size_t buf_sz);

/**
 * @brief
 * Extract and convert GPU evidence to base64 string.
 * @param evidence the pointer of GPU evidence
 * @param buf_evi the pointer of buffer to store base64 string
 * @param buf_sz the size of buffer
 * @return size_t
 */
size_t extract_nvgpu_evidence (evidence *evidence, char *buf_evi, size_t buf_sz);

/**
 * @brief
 * Extract and convert GPU certificate chain to base64 string.
 * @param certchain the pointer of GPU certificate chain
 * @param certchain_sz the size of GPU certificate chain
 * @param buf_certchain the pointer of buffer to store base64 string
 * @param buf_sz the size of buffer
 * @return size_t
 */
size_t extract_nvgpu_certchain (uint8_t *certchain, uint32_t certchain_sz, char *buf_certchain, size_t buf_sz);

/**
 * @brief
 * Generate JSON object for ITA NVGPU attestation.
 * @param evi the pointer of evidence
 * @param certchain the pointer of certificate chain
 * @param certchain_sz the size of certificate chain
 * @param nvgpu_nonce the pointer of GPU nonce
 * @param nvgpu_nonce_sz the size of GPU nonce
 * @param nonce the pointer of nonce as input
 * @param evi_jsonobj_ref the pointer reference of generated JSON object
 * @return the result status of generating JSON object
 */
int generate_nvgpu_jsonobj (evidence *evi, uint8_t *certchain, uint32_t certchain_sz, uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_sz, nonce *nonce,
                            json_t **evi_jsonobj_ref);

int sha256_hash (const unsigned char *data, size_t data_len, unsigned char *hash);
nvmlReturn_t nvgpu_generate_evidence (uint8_t *nonce, uint32_t nonce_len, uint8_t **evi, uint32_t *evi_sz, uint8_t **certchain, uint32_t *certschain_sz);
int generate_gpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, nonce *nonce);

int
nvgpu_adapter_new (evidence_adapter **adapter)
{
	nvgpu_adapter_context *ctx = NULL;

	if (NULL == adapter)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_ADAPTER;
	}

	*adapter = (evidence_adapter *)malloc (sizeof (evidence_adapter));
	if (NULL == *adapter)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	ctx = (nvgpu_adapter_context *)calloc (1, sizeof (nvgpu_adapter_context));
	if (NULL == ctx)
	{
		free (*adapter);
		*adapter = NULL;
		return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	(*adapter)->ctx = ctx;
	// it is not compatible with original signature since certchain is
	// required for NVGPU unless we added it into struct evidence
	(*adapter)->collect_evidence = NULL;
	(*adapter)->get_evidence = nvgpu_get_evidence;
	(*adapter)->get_evidence_identifier = nvgpu_get_evidence_identifier;

	return STATUS_OK;
}

const char *
nvgpu_get_evidence_identifier ()
{
	return EVIDENCE_IDENTIFIER_NVGPU;
}

int
nvgpu_collect_evidence (void *ctx, evidence *evidence, nonce *nonce, uint8_t **certchain, uint32_t *certchain_len, uint8_t **gpu_nonce, uint32_t *gpu_nonce_len,
                        uint8_t *user_data, uint32_t user_data_len)
{
	int status = 0;
	uint32_t retval = 0;
	uint8_t *evi = NULL;
	uint32_t evi_sz = 0;

	if (user_data != NULL || user_data_len > 0)
	{
		LOG ("User data is not supported for NVGPU\n");
	}

	nvgpu_adapter_context *nvgpu_ctx = NULL;

	if (NULL == ctx)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
	}

	if (NULL == certchain || NULL == certchain_len)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_CERTCHAIN;
	}

	if (NULL == evidence)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_EVIDENCE;
	}

	uint8_t *nvgpu_nonce = NULL;
	uint32_t nvgpu_nonce_len = 0;
	nvgpu_nonce_len = EVP_MD_size (EVP_sha256 ()); // 32 bytes
	nvgpu_nonce = (uint8_t *)calloc (1, nvgpu_nonce_len);
	if (NULL == nvgpu_nonce)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
	}

	char hex_nonce[nvgpu_nonce_len * 2 + 1];
	int nonce_ret = generate_gpu_nonce (nvgpu_nonce, nvgpu_nonce_len, nonce);
	if (nonce_ret != STATUS_OK)
	{
		ERROR ("Error: Failed to generate nonce\n");
		status = STATUS_NVGPU_ERROR_BASE | STATUS_NULL_NONCE;
		goto ADA_ERROR;
	}

	for (uint32_t i = 0; i < nvgpu_nonce_len; i++)
	{
		sprintf (&hex_nonce[i * 2], "%02x", nvgpu_nonce[i]);
	}
	hex_nonce[nvgpu_nonce_len * 2] = '\0';
	DEBUG ("Generated Adapter NVGPU Nonce: %s\n", hex_nonce);

	nvgpu_ctx = (nvgpu_adapter_context *)ctx;

	nvmlReturn_t ret = nvgpu_generate_evidence (nvgpu_nonce, nvgpu_nonce_len, &evi, &evi_sz, certchain, certchain_len);

	if (ret != NVML_SUCCESS)
	{
		ERROR ("Error: Failed to generate evidence: %s\n", nvmlErrorString (ret));
		status = STATUS_NVGPU_ERROR_BASE | STATUS_GEN_EVIDENCE_ERROR;
		goto ADA_ERROR;
	}

	evidence->type = EVIDENCE_TYPE_NVGPU;

	*gpu_nonce = nvgpu_nonce;
	*gpu_nonce_len = nvgpu_nonce_len;
	evidence->evidence = evi;
	evidence->evidence_len = evi_sz;

	return STATUS_OK;

ADA_ERROR:
	if (NULL != evi)
	{
		free (evi);
		evi = NULL;
		evi_sz = 0;
	}
	if (NULL != *certchain)
	{
		free (*certchain);
		*certchain = NULL;
		*certchain_len = 0;
	}
	if (NULL != nvgpu_nonce)
	{
		free (nvgpu_nonce);
		nvgpu_nonce = NULL;
		nvgpu_nonce_len = 0;
	}
	return status;
}

int
nvgpu_adapter_free (evidence_adapter *adapter)
{
	if (NULL == adapter)
	{
		return STATUS_OK;
	}

	if (NULL != adapter->ctx)
	{
		free (adapter->ctx);
		adapter->ctx = NULL;
	}

	free (adapter);
	adapter = NULL;
	return STATUS_OK;
}

int
sha256_hash (const unsigned char *data, size_t data_len, unsigned char *hash)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned int hash_len;

	md = EVP_sha256 ();
	mdctx = EVP_MD_CTX_new ();
	if (mdctx == NULL)
	{
		ERROR ("Error creating EVP_MD_CTX\n");
		return STATUS_INVOCATION_ERROR;
	}

	if (EVP_DigestInit_ex (mdctx, md, NULL) != 1)
	{
		ERROR ("Error initializing digest\n");
		EVP_MD_CTX_free (mdctx);
		return STATUS_INVOCATION_ERROR;
	}

	if (EVP_DigestUpdate (mdctx, data, data_len) != 1)
	{
		ERROR ("Error updating digest\n");
		EVP_MD_CTX_free (mdctx);
		return STATUS_INVOCATION_ERROR;
	}

	if (EVP_DigestFinal_ex (mdctx, hash, &hash_len) != 1)
	{
		ERROR ("Error finalizing digest\n");
		EVP_MD_CTX_free (mdctx);
		return STATUS_INVOCATION_ERROR;
	}

	EVP_MD_CTX_free (mdctx);
	assert (hash_len == 32);
	assert (NULL != hash);

	return STATUS_OK;
}

nvmlReturn_t
nvgpu_generate_evidence (uint8_t *nonce, uint32_t nonce_len, uint8_t **evi, uint32_t *evi_sz, uint8_t **certchain, uint32_t *certschain_sz)
{
	nvmlReturn_t result;
	unsigned int device_count, idx;

	if (NULL == evi || NULL == evi_sz || NULL == certchain || NULL == certschain_sz)
	{
		ERROR ("Invalid arguments\n");
		return NVML_ERROR_INVALID_ARGUMENT;
	}

	if (nonce_len != 32)
	{
		ERROR ("Invalid nonce length\n");
		return NVML_ERROR_INVALID_ARGUMENT;
	}

	// First initialize NVML library
	result = nvmlInit ();
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to initialize NVML: %s\n", nvmlErrorString (result));
		return result;
	}

	result = nvmlDeviceGetCount (&device_count);
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to query device count: %s\n", nvmlErrorString (result));
		nvmlShutdown ();
		return result;
	}

	if (device_count > 0)
	{
		if (device_count > 1)
		{
			LOG ("WARNING: Multiple NVIDIA GPUs found, only the first one will be "
			     "supported\n");
		}
		// only support single NVIDIA GPU for now
		device_count = 1;
		idx = 0;
	}
	else
	{
		ERROR ("No NVIDIA GPU found\n");
		nvmlShutdown ();
		return NVML_ERROR_NOT_SUPPORTED;
	}

	nvmlDevice_t device;

	// Query for device handle to perform operations on a device
	// You can also query device handle by other features like:
	// nvmlDeviceGetHandleBySerial
	// nvmlDeviceGetHandleByPciBusId
	result = nvmlDeviceGetHandleByIndex (idx, &device);
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to get handle for device %u: %s\n", idx, nvmlErrorString (result));
		nvmlShutdown ();
		return result;
	}

	nvmlConfComputeGpuAttestationReport_t report;

	memset (&report, 0, sizeof (report));

	memcpy (report.nonce, nonce, nonce_len);

	result = nvmlDeviceGetConfComputeGpuAttestationReport (device, &report);
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to get attestation report: %s\n", nvmlErrorString (result));
		goto GEN_EVI_ERROR;
	}

	*evi = calloc (1, report.attestationReportSize);
	if (NULL == *evi)
	{
		ERROR ("Failed to allocate memory for evidence\n");
		result = NVML_ERROR_MEMORY;
		goto GEN_EVI_ERROR;
	}

	memcpy (*evi, report.attestationReport, report.attestationReportSize);
	*evi_sz = report.attestationReportSize;

	nvmlConfComputeGpuCertificate_t cert;
	memset (&cert, 0, sizeof (cert));
	result = nvmlDeviceGetConfComputeGpuCertificate (device, &cert);
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to get attestation report: %s\n", nvmlErrorString (result));
		goto GEN_EVI_ERROR;
	}

	*certchain = calloc (1, cert.attestationCertChainSize);
	if (NULL == *certchain)
	{
		ERROR ("Failed to allocate memory for certchain\n");
		result = NVML_ERROR_MEMORY;
		goto GEN_EVI_ERROR;
	}

	memcpy (*certchain, cert.attestationCertChain, cert.attestationCertChainSize);
	*certschain_sz = cert.attestationCertChainSize;

	result = nvmlShutdown ();
	if (NVML_SUCCESS != result)
	{
		ERROR ("Failed to shutdown NVML: %s\n", nvmlErrorString (result));
		goto GEN_EVI_ERROR;
	}
	return NVML_SUCCESS;

GEN_EVI_ERROR:
	if (NULL != *evi)
	{
		free (*evi);
		*evi = NULL;
		*evi_sz = 0;
	}
	if (NULL != *certchain)
	{
		free (*certchain);
		*certchain = NULL;
		*certschain_sz = 0;
	}
	nvmlShutdown ();
	return result;
}

/*
 * This utility function generates a GPU nonce in case there is no gpu nonce
 * provided. If nonce->val and nonce->iat are provided, the GPU nonce is
 * generated by hashing the concatenation of nonce->val and nonce->iat. If
 * nonce->val and nonce->iat are not provided, a random nonce is generated.
 */
int
generate_gpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, nonce *nonce)
{
	uint32_t nonce_data_len = 0;
	uint8_t *nonce_data = NULL;

	if (NULL == nvgpu_nonce || nvgpu_nonce_len != 32)
	{
		return STATUS_NVGPU_ERROR_BASE | STATUS_INVALID_PARAMETER;
	}

	if (NULL != nonce)
	{
		// the nvgpu nonce is either provided or generated from nonce->val and
		// nonce->iat
		if (nonce->val == NULL || nonce->val_len == 0 || nonce->iat == NULL || nonce->iat_len == 0)
		{
			// generate random nonce as gpu nonce
			if (RAND_bytes (nvgpu_nonce, nvgpu_nonce_len) != 1)
			{
				return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
			}
		}
		else
		{
			// append nonce->val and nonce->iat
			nonce_data_len = nonce->val_len + nonce->iat_len;
			nonce_data = (uint8_t *)calloc (1, (nonce_data_len + 1) * sizeof (uint8_t));
			if (NULL == nonce_data)
			{
				return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
			}

			memcpy (nonce_data, nonce->val, nonce->val_len);
			memcpy (nonce_data + nonce->val_len, nonce->iat, nonce->iat_len);

			int ret = sha256_hash (nonce_data, nonce_data_len, nvgpu_nonce);
			if (ret != STATUS_OK)
			{
				free (nonce_data);
				nonce_data = NULL;
				nonce_data_len = 0;
				return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
			}
		}
	}
	else
	{
		// generate random nonce as gpu nonce
		if (RAND_bytes (nvgpu_nonce, nvgpu_nonce_len) != 1)
		{
			return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
		}
	}
	return STATUS_OK;
}

size_t
extract_nvgpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, char *buf_nonce, size_t buf_sz)
{
	if (NULL == buf_nonce)
	{
		ERROR ("Error: Invalid arguments\n");
		return 0;
	}
	if (nvgpu_nonce_len == 0 || nvgpu_nonce == NULL)
	{
		ERROR ("Error: NVGPU Nonce is not available\n");
		return 0;
	}
	if (nvgpu_nonce_len != 32)
	{
		ERROR ("Error: Invalid NVGPU Nonce length\n");
		return 0;
	}
	if (buf_sz < (nvgpu_nonce_len * 2 + 1))
	{
		ERROR ("Error: Insufficient buffer size\n");
		return 0;
	}
	int ret = OPENSSL_buf2hexstr_ex (buf_nonce, buf_sz, NULL, nvgpu_nonce, nvgpu_nonce_len, 0);
	if (ret = !1)
	{
		ERROR ("Error converting binary to hex string\n");
		return 0;
	}
	return strlen (buf_nonce);
}

size_t
extract_nvgpu_evidence (evidence *evidence, char *buf_evi, size_t buf_sz)
{
	if (NULL == evidence || NULL == buf_evi)
	{
		ERROR ("Error: Invalid arguments\n");
		return 0;
	}
	if (evidence->evidence_len == 0 || evidence->evidence == NULL)
	{
		ERROR ("Error: NVGPU Evidence is not available\n");
		return 0;
	}
	size_t exp_buf_sz = ((evidence->evidence_len * 2) + 2) / 3 * 4 + 1;
	if (buf_sz < exp_buf_sz)
	{
		ERROR ("Error: Insufficient buffer size for evidence extraction (expected: "
		       ">= %ld)\n",
		       exp_buf_sz);
		return 0;
	}
	size_t hex_evi_sz = evidence->evidence_len * 2 + 1;
	char *hex_evi = calloc (1, hex_evi_sz);
	if (hex_evi == NULL)
	{
		ERROR ("Error: Failed to allocate memory for hex encoded evidence")
		return 0;
	}
	int hex_ret = OPENSSL_buf2hexstr_ex (hex_evi, hex_evi_sz, NULL, evidence->evidence, evidence->evidence_len, 0);
	if (hex_ret != 1)
	{
		free (hex_evi);
		hex_evi = NULL;
		hex_evi_sz = 0;
		ERROR ("Error converting binary to hex string\n");
		return 0;
	}

	int input_length = strlen (hex_evi);
	// LOG("Info: hex size: %ld -- expected: %d \n%s", strlen(hex_evi),
	// evidence->evidence_len * 2, hex_evi);
	if (input_length != evidence->evidence_len * 2)
	{
		ERROR ("Error: Invalid hex encoded evidence length\n");
		return 0;
	}

	DEBUG ("Info: buffer size: %ld -- expected: %d\n", buf_sz, (input_length + 2) / 3 * 4 + 1);
	if ((buf_sz < ((input_length + 2) / 3) * 4 + 1))
	{
		ERROR ("Error: Insufficient buffer size for base64 encoding\n");
		return 0;
	}

	int encoded_len = EVP_EncodeBlock ((unsigned char *)buf_evi, hex_evi, input_length);
	if (encoded_len == -1)
	{
		ERROR ("Error: Failed to base64 encoded evidence\n")
		return 0;
	}
	free (hex_evi);
	return encoded_len;
}

size_t
extract_nvgpu_certchain (uint8_t *certchain, uint32_t certchain_sz, char *buf_certchain, size_t buf_sz)
{
	if (NULL == buf_certchain)
	{
		ERROR ("Error: Invalid arguments\n");
		return 0;
	}
	if (certchain_sz == 0 || certchain == NULL)
	{
		ERROR ("Error: NVGPU Certificate Chain is not available\n");
		return 0;
	}
	size_t exp_buf_sz = ((certchain_sz + 2) / 3) * 4 + 1;
	if (buf_sz < exp_buf_sz)
	{
		ERROR ("Error: Insufficient buffer size for certchain extraction (expected "
		       ">= %ld)\n",
		       exp_buf_sz);
		return 0;
	}
	int encoded_len = EVP_EncodeBlock ((unsigned char *)buf_certchain, certchain, certchain_sz);
	if (encoded_len == -1)
	{
		ERROR ("Error: Failed to base64 encoded certicate chain \n")
		return 0;
	}
	return encoded_len;
}

int
generate_nvgpu_jsonobj (evidence *evi, uint8_t *certchain, uint32_t certchain_sz, uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_sz, nonce *nonce,
                        json_t **evi_jsonobj_ref)
{
	int use_gpu_nonce = -1;
	if (NULL == evi || NULL == nonce || NULL == evi_jsonobj_ref || NULL != *evi_jsonobj_ref)
	{
		ERROR ("Error: Invalid arguments for generating NVGPU JSON request\n");
		return STATUS_INVALID_PARAMETER;
	}

	assert (nvgpu_nonce_sz == 32);
	size_t buf_nonce_sz = nvgpu_nonce_sz * 2 + 1;
	char buf_nonce[buf_nonce_sz];
	json_t *verified_nonce_json = NULL;
	if (nonce->val == NULL || nonce->val_len == 0 || nonce->iat == NULL || nonce->iat_len == 0)
	{
		memset (buf_nonce, 0, buf_nonce_sz);
		size_t ret_nonce_sz = extract_nvgpu_nonce (nvgpu_nonce, nvgpu_nonce_sz, buf_nonce, buf_nonce_sz);
		if (ret_nonce_sz == 0)
		{
			ERROR ("Error: Failed to extract nonce\n");
			return STATUS_INVALID_PARAMETER;
		}
		use_gpu_nonce = 1;
	}
	else
	{
		int res = get_jansson_nonce (nonce, &verified_nonce_json);
		if (res != STATUS_OK)
		{
			ERROR ("Error: Failed to create nonce json: 0x%04x\n", res);
			return STATUS_INVALID_PARAMETER;
		}
		use_gpu_nonce = 0;
	}

	const size_t buf_evi_sz = ((evi->evidence_len * 2) + 2) / 3 * 4 + 1;
	char buf_evi[buf_evi_sz];
	memset (buf_evi, 0, buf_evi_sz);
	size_t ret_evi_sz = extract_nvgpu_evidence (evi, buf_evi, buf_evi_sz);
	if (ret_evi_sz == 0)
	{
		ERROR ("Error: Failed to extract evidence\n");
		return STATUS_INVALID_PARAMETER;
	}

	const size_t buf_certchain_sz = ((certchain_sz + 2) / 3) * 4 + 1;
	char buf_certchain[buf_certchain_sz];
	memset (buf_certchain, 0, buf_certchain_sz);
	size_t ret_certchain_sz = extract_nvgpu_certchain (certchain, certchain_sz, buf_certchain, buf_certchain_sz);
	if (ret_certchain_sz == 0)
	{
		ERROR ("Error: Failed to extract certificate chain\n");
		return STATUS_INVALID_PARAMETER;
	}

	*evi_jsonobj_ref = json_object ();

	if (use_gpu_nonce == 1)
	{
		if (0 != json_object_set (*evi_jsonobj_ref, "gpu_nonce", json_string (buf_nonce)))
		{
			ERROR("Error: Failed to set gpu_nonce");
			return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
		}
	}
	else if (use_gpu_nonce == 0)
	{
		if (0 != json_object_set (*evi_jsonobj_ref, "verifier_nonce", verified_nonce_json))
		{
			ERROR("Error: Failed to set verifier_nonce");
			return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
		}
		json_decref (verified_nonce_json);
		verified_nonce_json = NULL;
	}
	else
	{
		ERROR ("Error: Invalid nonce\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (0 != json_object_set (*evi_jsonobj_ref, "arch", json_string ("HOPPER")))
	{
		ERROR("Error: Failed to set arch");
		return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
	}
	if (0 != json_object_set (*evi_jsonobj_ref, "evidence", json_string (buf_evi)))
	{
		ERROR("Error: Failed to set evidence");
		return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
	}
	if (0 != json_object_set (*evi_jsonobj_ref, "certificate", json_string (buf_certchain)))
	{
		ERROR("Error: Failed to set certificate");
		return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
	}

	return STATUS_OK;
}

int
nvgpu_get_evidence (void *ctx, json_t *evidence_jsonobj_ref, nonce *nonce, uint8_t *user_data, uint32_t user_data_len)
{
	// if (NULL == ctx || NULL == evidence_jsonobj_ref || NULL == nonce)
	if (NULL == ctx || NULL == evidence_jsonobj_ref)
	{
		ERROR ("Error: Invalid arguments for NVGPU evidence request\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (user_data != NULL || user_data_len > 0)
	{
		LOG ("User data is not supported for NVGPU\n");
	}

	evidence evi = { 0 };
	uint8_t *certchain = NULL;
	uint32_t certchain_sz = 0;
	uint8_t *gpu_nonce = NULL;
	uint32_t gpu_nonce_sz = 0;

	int status = nvgpu_collect_evidence (ctx, &evi, nonce, &certchain, &certchain_sz, &gpu_nonce, &gpu_nonce_sz, NULL, 0);
	if (STATUS_OK != status)
	{
		ERROR ("Error: Failed to collect evidence or nonce from adapter 0x%04x\n", status);
		return STATUS_INVOCATION_ERROR;
	}

	json_t *evi_jsonobj = NULL;
	int ret = generate_nvgpu_jsonobj (&evi, certchain, certchain_sz, gpu_nonce, gpu_nonce_sz, nonce, &evi_jsonobj);
	if (ret != STATUS_OK)
	{
		ERROR ("Error: Failed to generate NVGPU JSON object\n");
		return STATUS_INVOCATION_ERROR;
	}

	const char *key;
	json_t *value;
	json_object_foreach (evi_jsonobj, key, value) { 
		if (0 != json_object_set (evidence_jsonobj_ref, key, value))
		{
			ERROR ("Error: Failed to set JSON object\n");
			return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
		}	
	}
	json_decref (evi_jsonobj);

	return STATUS_OK;
}
