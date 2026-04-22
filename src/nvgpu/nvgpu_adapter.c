/*
 * Copyright (C) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <assert.h>
#include <json.h>
#include <log.h>
#include <nvgpu_adapter.h>
#include <nvml.h>
#include <openssl/evp.h>

/* NVML_DEVICE_ARCH_BLACKWELL was added after CUDA 13.1; provide a fallback so
 * the code compiles with older nvml-dev packages while still running correctly
 * on hardware where the runtime NVML reports the correct architecture value. */
#ifndef NVML_DEVICE_ARCH_BLACKWELL
#define NVML_DEVICE_ARCH_BLACKWELL 10
#endif
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

/**
 * @brief Per-device evidence collected from a single GPU.
 *
 * All pointer members are heap-allocated and must be freed via
 * gpu_device_evidence_array_free() when no longer needed.
 */
typedef struct gpu_device_evidence
{
        uint8_t  *report;                                        /* raw attestation report bytes */
        uint32_t  report_len;
        uint8_t  *certchain;                                     /* raw certificate chain bytes */
        uint32_t  certchain_len;
        char      arch[32];                                      /* lowercase arch: "hopper" or "blackwell" */
        char      firmware_version[NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE]; /* VBIOS version string */
} gpu_device_evidence;

/* ----------- Forward declarations ----------- */

static int nvgpu_collect_evidence (void *ctx, gpu_device_evidence **out_items, uint32_t *out_count,
                            uint8_t **gpu_nonce, uint32_t *gpu_nonce_len,
                            nonce *nonce, uint8_t *user_data, uint32_t user_data_len);

static size_t extract_nvgpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, char *buf_nonce, size_t buf_sz);
static size_t extract_bytes_to_base64 (const uint8_t *data, uint32_t data_len, char *buf, size_t buf_sz);
static int generate_nvgpu_jsonobj (gpu_device_evidence *items, uint32_t item_count,
                            uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_sz,
                            nonce *nonce, json_t **evi_jsonobj_ref);
static int sha256_hash (const unsigned char *data, size_t data_len, unsigned char *hash);
static nvmlReturn_t nvgpu_generate_evidence (uint8_t *nonce, uint32_t nonce_len,
                                      gpu_device_evidence **out_items, uint32_t *out_count);
static int generate_gpu_nonce (uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_len, nonce *nonce);

/* ----------- Internal helpers ----------- */

/**
 * @brief Map an NVML device architecture value to a lowercase string.
 */
static const char *
arch_to_string (nvmlDeviceArchitecture_t arch)
{
        switch (arch)
        {
        case NVML_DEVICE_ARCH_HOPPER:
                return "hopper";
        case NVML_DEVICE_ARCH_BLACKWELL:
                return "blackwell";
        default:
                return "unknown";
        }
}

/**
 * @brief Free an array of gpu_device_evidence items and all their heap members.
 * @param items  array returned by nvgpu_generate_evidence (may be NULL)
 * @param count  number of valid entries in items
 */
static void
gpu_device_evidence_array_free (gpu_device_evidence *items, uint32_t count)
{
        if (NULL == items)
        {
                return;
        }
        for (uint32_t i = 0; i < count; i++)
        {
                if (NULL != items[i].report)
                {
                        free (items[i].report);
                        items[i].report = NULL;
                }
                if (NULL != items[i].certchain)
                {
                        free (items[i].certchain);
                        items[i].certchain = NULL;
                }
        }
        free (items);
}

/* ----------- Adapter lifecycle ----------- */

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
        /* collect_evidence uses its own multi-GPU path; the generic collect_evidence
           pointer is not used for NVGPU. */
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

/* ----------- Crypto utilities ----------- */

static int
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

/* ----------- Multi-GPU evidence collection ----------- */

/*
 * Collect raw attestation reports and certificate chains from all supported GPUs.
 * Supports Hopper (H100/H200) and Blackwell (B100/B200) architectures.
 * Any unsupported architecture causes an immediate error (no partial results).
 */
static nvmlReturn_t
nvgpu_generate_evidence (uint8_t *nonce, uint32_t nonce_len,
                         gpu_device_evidence **out_items, uint32_t *out_count)
{
        nvmlReturn_t result;
        unsigned int device_count;

        if (NULL == nonce || NULL == out_items || NULL == out_count)
        {
                ERROR ("Invalid arguments\n");
                return NVML_ERROR_INVALID_ARGUMENT;
        }

        if (nonce_len != 32)
        {
                ERROR ("Invalid nonce length: expected 32, got %u\n", nonce_len);
                return NVML_ERROR_INVALID_ARGUMENT;
        }

        *out_items = NULL;
        *out_count = 0;

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

        if (device_count == 0)
        {
                ERROR ("No NVIDIA GPU found\n");
                nvmlShutdown ();
                return NVML_ERROR_NOT_SUPPORTED;
        }

        gpu_device_evidence *items = (gpu_device_evidence *)calloc (device_count, sizeof (gpu_device_evidence));
        if (NULL == items)
        {
                ERROR ("Failed to allocate per-device evidence array\n");
                nvmlShutdown ();
                return NVML_ERROR_MEMORY;
        }

        uint32_t filled = 0;

        for (unsigned int i = 0; i < device_count; i++)
        {
                nvmlDevice_t device;
                result = nvmlDeviceGetHandleByIndex (i, &device);
                if (NVML_SUCCESS != result)
                {
                        ERROR ("Failed to get handle for device %u: %s\n", i, nvmlErrorString (result));
                        goto GEN_EVI_ERROR;
                }

                nvmlDeviceArchitecture_t device_arch;
                result = nvmlDeviceGetArchitecture (device, &device_arch);
                if (NVML_SUCCESS != result)
                {
                        ERROR ("Failed to get architecture of device %u: %s\n", i, nvmlErrorString (result));
                        goto GEN_EVI_ERROR;
                }

                if (device_arch != NVML_DEVICE_ARCH_HOPPER && device_arch != NVML_DEVICE_ARCH_BLACKWELL)
                {
                        ERROR ("Device %u has unsupported architecture (only Hopper and Blackwell are supported)\n", i);
                        result = NVML_ERROR_NOT_SUPPORTED;
                        goto GEN_EVI_ERROR;
                }

                strncpy (items[filled].arch, arch_to_string (device_arch), sizeof (items[filled].arch) - 1);
                items[filled].arch[sizeof (items[filled].arch) - 1] = '\0';

                /* Retrieve VBIOS / firmware version (non-fatal if unavailable) */
                result = nvmlDeviceGetVbiosVersion (device, items[filled].firmware_version,
                                                    sizeof (items[filled].firmware_version));
                if (NVML_SUCCESS != result)
                {
                        LOG ("WARNING: Failed to get VBIOS version for device %u: %s\n", i, nvmlErrorString (result));
                        items[filled].firmware_version[0] = '\0';
                        result = NVML_SUCCESS;
                }

                /* Collect the attestation report */
                nvmlConfComputeGpuAttestationReport_t report;
                memset (&report, 0, sizeof (report));
                memcpy (report.nonce, nonce, nonce_len);

                result = nvmlDeviceGetConfComputeGpuAttestationReport (device, &report);
                if (NVML_SUCCESS != result)
                {
                        ERROR ("Failed to get attestation report for device %u: %s\n", i, nvmlErrorString (result));
                        goto GEN_EVI_ERROR;
                }

                items[filled].report = (uint8_t *)calloc (1, report.attestationReportSize);
                if (NULL == items[filled].report)
                {
                        ERROR ("Failed to allocate memory for report of device %u\n", i);
                        result = NVML_ERROR_MEMORY;
                        goto GEN_EVI_ERROR;
                }
                memcpy (items[filled].report, report.attestationReport, report.attestationReportSize);
                items[filled].report_len = report.attestationReportSize;

                /* Collect the certificate chain */
                nvmlConfComputeGpuCertificate_t cert;
                memset (&cert, 0, sizeof (cert));
                result = nvmlDeviceGetConfComputeGpuCertificate (device, &cert);
                if (NVML_SUCCESS != result)
                {
                        ERROR ("Failed to get certificate chain for device %u: %s\n", i, nvmlErrorString (result));
                        /* items[filled].report is allocated but filled not yet incremented;
                         * GEN_EVI_ERROR only frees items[0..filled-1], so free it here. */
                        free (items[filled].report);
                        items[filled].report = NULL;
                        goto GEN_EVI_ERROR;
                }

                items[filled].certchain = (uint8_t *)calloc (1, cert.attestationCertChainSize);
                if (NULL == items[filled].certchain)
                {
                        ERROR ("Failed to allocate memory for certchain of device %u\n", i);
                        result = NVML_ERROR_MEMORY;
                        free (items[filled].report);
                        items[filled].report = NULL;
                        goto GEN_EVI_ERROR;
                }
                memcpy (items[filled].certchain, cert.attestationCertChain, cert.attestationCertChainSize);
                items[filled].certchain_len = cert.attestationCertChainSize;

                filled++;
        }

        result = nvmlShutdown ();
        if (NVML_SUCCESS != result)
        {
                ERROR ("Failed to shutdown NVML: %s\n", nvmlErrorString (result));
                goto GEN_EVI_ERROR;
        }

        *out_items = items;
        *out_count = filled;
        return NVML_SUCCESS;

GEN_EVI_ERROR:
        gpu_device_evidence_array_free (items, filled);
        nvmlShutdown ();
        return result;
}

/*
 * This utility function generates a GPU nonce. If nonce->val and nonce->iat are
 * provided, the GPU nonce is generated by hashing their concatenation. Otherwise
 * a random nonce is generated.
 */
static int
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
                if (nonce->val == NULL || nonce->val_len == 0 || nonce->iat == NULL || nonce->iat_len == 0)
                {
                        if (RAND_bytes (nvgpu_nonce, nvgpu_nonce_len) != 1)
                        {
                                return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
                        }
                }
                else
                {
                        nonce_data_len = nonce->val_len + nonce->iat_len;
                        nonce_data = (uint8_t *)calloc (1, (nonce_data_len + 1) * sizeof (uint8_t));
                        if (NULL == nonce_data)
                        {
                                return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
                        }

                        memcpy (nonce_data, nonce->val, nonce->val_len);
                        memcpy (nonce_data + nonce->val_len, nonce->iat, nonce->iat_len);

                        int ret = sha256_hash (nonce_data, nonce_data_len, nvgpu_nonce);
                        free (nonce_data);
                        nonce_data = NULL;

                        if (ret != STATUS_OK)
                        {
                                return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
                        }
                }
        }
        else
        {
                if (RAND_bytes (nvgpu_nonce, nvgpu_nonce_len) != 1)
                {
                        return STATUS_NVGPU_ERROR_BASE | STATUS_INVOCATION_ERROR;
                }
        }
        return STATUS_OK;
}

/* ----------- Encoding utilities ----------- */

static size_t
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
        /* OPENSSL_buf2hexstr_ex is only available in OpenSSL 3.0+.
         * Use a portable loop to produce a lowercase hex string without separators. */
        for (uint32_t i = 0; i < nvgpu_nonce_len; i++)
        {
                snprintf (buf_nonce + i * 2, 3, "%02x", nvgpu_nonce[i]);
        }
        buf_nonce[nvgpu_nonce_len * 2] = '\0';
        return strlen (buf_nonce);
}

/*
 * Base64-encode a raw byte buffer directly.
 * The evidence field in the ITA request body is base64(raw_report_bytes) —
 * no intermediate hex encoding is applied.
 */
static size_t
extract_bytes_to_base64 (const uint8_t *data, uint32_t data_len, char *buf, size_t buf_sz)
{
        if (NULL == data || NULL == buf)
        {
                ERROR ("Error: Invalid arguments\n");
                return 0;
        }
        if (data_len == 0)
        {
                ERROR ("Error: Input data is empty\n");
                return 0;
        }
        size_t exp_buf_sz = ((data_len + 2) / 3) * 4 + 1;
        if (buf_sz < exp_buf_sz)
        {
                ERROR ("Error: Insufficient buffer size for base64 encoding (expected >= %zu)\n", exp_buf_sz);
                return 0;
        }
        int encoded_len = EVP_EncodeBlock ((unsigned char *)buf, data, (int)data_len);
        if (encoded_len <= 0)
        {
                ERROR ("Error: Failed to base64-encode data\n");
                return 0;
        }
        return (size_t)encoded_len;
}

/* ----------- JSON object generation ----------- */

/*
 * Build the ITA NVGPU attestation JSON body using the new evidence_list schema:
 *
 * {
 *   "gpu_nonce": "<hex>",          // or "verifier_nonce": { ... }
 *   "arch": "hopper",              // from the first device, lowercase
 *   "evidence_list": [
 *     {
 *       "evidence": "<base64>",
 *       "certificate": "<base64>",
 *       "firmware_version": "<string>"   // omitted when empty
 *     },
 *     ...
 *   ]
 * }
 */
static int
generate_nvgpu_jsonobj (gpu_device_evidence *items, uint32_t item_count,
                        uint8_t *nvgpu_nonce, uint32_t nvgpu_nonce_sz,
                        nonce *nonce, json_t **evi_jsonobj_ref)
{
        int use_gpu_nonce = -1;

        if (NULL == items || item_count == 0 || NULL == nvgpu_nonce || nvgpu_nonce_sz != 32
            || NULL == nonce || NULL == evi_jsonobj_ref || NULL != *evi_jsonobj_ref)
        {
                ERROR ("Error: Invalid arguments for generating NVGPU JSON request\n");
                return STATUS_INVALID_PARAMETER;
        }
        /* nvgpu_nonce_sz is validated to 32 above; buffer is 32*2+1 = 65 bytes */
        char buf_nonce[65];
        json_t *verified_nonce_json = NULL;

        if (nonce->val == NULL || nonce->val_len == 0 || nonce->iat == NULL || nonce->iat_len == 0
            || nonce->signature == NULL || nonce->signature_len == 0)
        {
                memset (buf_nonce, 0, sizeof (buf_nonce));
                size_t ret_nonce_sz = extract_nvgpu_nonce (
                    nvgpu_nonce, nvgpu_nonce_sz, buf_nonce, sizeof (buf_nonce));
                if (ret_nonce_sz == 0)
                {
                        ERROR ("Error: Failed to extract GPU nonce\n");
                        return STATUS_INVALID_PARAMETER;
                }
                use_gpu_nonce = 1;
        }
        else
        {
                int res = get_jansson_nonce (nonce, &verified_nonce_json);
                if (res != STATUS_OK)
                {
                        ERROR ("Error: Failed to create nonce JSON: 0x%04x\n", res);
                        return STATUS_INVALID_PARAMETER;
                }
                use_gpu_nonce = 0;
        }

        json_t *evidence_list = json_array ();
        if (NULL == evidence_list)
        {
                ERROR ("Error: Failed to allocate evidence_list JSON array\n");
                if (verified_nonce_json != NULL)
                {
                        json_decref (verified_nonce_json);
                }
                return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        }

        for (uint32_t i = 0; i < item_count; i++)
        {
                const size_t buf_evi_sz = ((items[i].report_len + 2) / 3) * 4 + 1;
                char *buf_evi = (char *)calloc (1, buf_evi_sz);
                if (NULL == buf_evi)
                {
                        ERROR ("Error: Failed to allocate evidence buffer for device %u\n", i);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
                }

                size_t ret_evi_sz = extract_bytes_to_base64 (items[i].report, items[i].report_len, buf_evi, buf_evi_sz);
                if (ret_evi_sz == 0)
                {
                        ERROR ("Error: Failed to encode evidence for device %u\n", i);
                        free (buf_evi);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_INVALID_PARAMETER;
                }

                const size_t buf_cert_sz = ((items[i].certchain_len + 2) / 3) * 4 + 1;
                char *buf_cert = (char *)calloc (1, buf_cert_sz);
                if (NULL == buf_cert)
                {
                        ERROR ("Error: Failed to allocate certchain buffer for device %u\n", i);
                        free (buf_evi);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
                }

                size_t ret_cert_sz = extract_bytes_to_base64 (items[i].certchain, items[i].certchain_len, buf_cert, buf_cert_sz);
                if (ret_cert_sz == 0)
                {
                        ERROR ("Error: Failed to encode certchain for device %u\n", i);
                        free (buf_evi);
                        free (buf_cert);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_INVALID_PARAMETER;
                }

                json_t *entry = json_object ();
                if (NULL == entry)
                {
                        ERROR ("Error: Failed to allocate evidence_list entry for device %u\n", i);
                        free (buf_evi);
                        free (buf_cert);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
                }

                json_t *js_evi = json_string (buf_evi);
                free (buf_evi);
                buf_evi = NULL;
                if (NULL == js_evi || 0 != json_object_set_new (entry, "evidence", js_evi))
                {
                        ERROR ("Error: Failed to set evidence for device %u\n", i);
                        if (js_evi != NULL) { json_decref (js_evi); }
                        free (buf_cert);
                        json_decref (entry);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }

                json_t *js_cert = json_string (buf_cert);
                free (buf_cert);
                buf_cert = NULL;
                if (NULL == js_cert || 0 != json_object_set_new (entry, "certificate", js_cert))
                {
                        ERROR ("Error: Failed to set certificate for device %u\n", i);
                        if (js_cert != NULL) { json_decref (js_cert); }
                        json_decref (entry);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }

                if (items[i].firmware_version[0] != '\0')
                {
                        if (0 != json_object_set_new (entry, "firmware_version", json_string (items[i].firmware_version)))
                        {
                                ERROR ("Error: Failed to set firmware_version for device %u\n", i);
                                json_decref (entry);
                                json_decref (evidence_list);
                                if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                                return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                        }
                }

                if (0 != json_array_append_new (evidence_list, entry))
                {
                        ERROR ("Error: Failed to append evidence entry for device %u\n", i);
                        json_decref (entry);
                        json_decref (evidence_list);
                        if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }
        }

        *evi_jsonobj_ref = json_object ();
        if (NULL == *evi_jsonobj_ref)
        {
                ERROR ("Error: Failed to allocate top-level JSON object\n");
                json_decref (evidence_list);
                if (verified_nonce_json != NULL) { json_decref (verified_nonce_json); }
                return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        }

        if (use_gpu_nonce == 1)
        {
                if (0 != json_object_set_new (*evi_jsonobj_ref, "gpu_nonce", json_string (buf_nonce)))
                {
                        ERROR ("Error: Failed to set gpu_nonce\n");
                        json_decref (*evi_jsonobj_ref);
                        *evi_jsonobj_ref = NULL;
                        json_decref (evidence_list);
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }
        }
        else
        {
                if (0 != json_object_set_new (*evi_jsonobj_ref, "verifier_nonce", verified_nonce_json))
                {
                        ERROR ("Error: Failed to set verifier_nonce\n");
                        json_decref (*evi_jsonobj_ref);
                        *evi_jsonobj_ref = NULL;
                        json_decref (verified_nonce_json);
                        json_decref (evidence_list);
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }
                verified_nonce_json = NULL; /* ownership transferred */
        }

        /* arch is taken from the first device */
        if (0 != json_object_set_new (*evi_jsonobj_ref, "arch", json_string (items[0].arch)))
        {
                ERROR ("Error: Failed to set arch\n");
                json_decref (*evi_jsonobj_ref);
                *evi_jsonobj_ref = NULL;
                json_decref (evidence_list);
                return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
        }

        if (0 != json_object_set_new (*evi_jsonobj_ref, "evidence_list", evidence_list))
        {
                ERROR ("Error: Failed to set evidence_list\n");
                json_decref (*evi_jsonobj_ref);
                *evi_jsonobj_ref = NULL;
                json_decref (evidence_list);
                return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
        }
        evidence_list = NULL; /* ownership transferred */

        return STATUS_OK;
}

/* ----------- Adapter entry points ----------- */

static int
nvgpu_collect_evidence (void *ctx, gpu_device_evidence **out_items, uint32_t *out_count,
                        uint8_t **gpu_nonce, uint32_t *gpu_nonce_len,
                        nonce *nonce, uint8_t *user_data, uint32_t user_data_len)
{
        if (user_data != NULL || user_data_len > 0)
        {
                LOG ("User data is not supported for NVGPU\n");
        }

        if (NULL == ctx)
        {
                return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_ADAPTER_CTX;
        }

        if (NULL == out_items || NULL == out_count || NULL == gpu_nonce || NULL == gpu_nonce_len)
        {
                return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_EVIDENCE;
        }

        uint32_t nvgpu_nonce_len = (uint32_t)EVP_MD_size (EVP_sha256 ()); /* 32 bytes */
        uint8_t *nvgpu_nonce = (uint8_t *)calloc (1, nvgpu_nonce_len);
        if (NULL == nvgpu_nonce)
        {
                return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
        }

        int nonce_ret = generate_gpu_nonce (nvgpu_nonce, nvgpu_nonce_len, nonce);
        if (nonce_ret != STATUS_OK)
        {
                ERROR ("Error: Failed to generate GPU nonce\n");
                free (nvgpu_nonce);
                return STATUS_NVGPU_ERROR_BASE | STATUS_NULL_NONCE;
        }

        char hex_nonce[nvgpu_nonce_len * 2 + 1];
        for (uint32_t i = 0; i < nvgpu_nonce_len; i++)
        {
                sprintf (&hex_nonce[i * 2], "%02x", nvgpu_nonce[i]);
        }
        hex_nonce[nvgpu_nonce_len * 2] = '\0';
        DEBUG ("Generated Adapter NVGPU Nonce: %s\n", hex_nonce);

        nvmlReturn_t ret = nvgpu_generate_evidence (nvgpu_nonce, nvgpu_nonce_len, out_items, out_count);
        if (ret != NVML_SUCCESS)
        {
                ERROR ("Error: Failed to generate evidence: %s\n", nvmlErrorString (ret));
                free (nvgpu_nonce);
                return STATUS_NVGPU_ERROR_BASE | STATUS_GEN_EVIDENCE_ERROR;
        }

        *gpu_nonce = nvgpu_nonce;
        *gpu_nonce_len = nvgpu_nonce_len;
        return STATUS_OK;
}

int
nvgpu_get_evidence (void *ctx, json_t *evidence_jsonobj_ref, nonce *nonce, uint8_t *user_data, uint32_t user_data_len)
{
        if (NULL == ctx || NULL == evidence_jsonobj_ref)
        {
                ERROR ("Error: Invalid arguments for NVGPU evidence request\n");
                return STATUS_INVALID_PARAMETER;
        }

        if (user_data != NULL || user_data_len > 0)
        {
                LOG ("User data is not supported for NVGPU\n");
        }

        gpu_device_evidence *items = NULL;
        uint32_t item_count = 0;
        uint8_t *gpu_nonce = NULL;
        uint32_t gpu_nonce_sz = 0;
        /* "nonce" parameter shadows the typedef; use struct keyword to declare a local */
        struct nonce empty_nonce;
        memset (&empty_nonce, 0, sizeof (empty_nonce));
        struct nonce *nonce_ptr = (nonce != NULL) ? nonce : &empty_nonce;

        int status = nvgpu_collect_evidence (ctx, &items, &item_count,
                                             &gpu_nonce, &gpu_nonce_sz,
                                             nonce_ptr, user_data, user_data_len);
        if (STATUS_OK != status)
        {
                ERROR ("Error: Failed to collect evidence from adapter: 0x%04x\n", status);
                return status;
        }

        json_t *evi_jsonobj = NULL;
        int ret = generate_nvgpu_jsonobj (items, item_count, gpu_nonce, gpu_nonce_sz,
                                          nonce_ptr, &evi_jsonobj);

        gpu_device_evidence_array_free (items, item_count);
        items = NULL;

        free (gpu_nonce);
        gpu_nonce = NULL;

        if (ret != STATUS_OK)
        {
                ERROR ("Error: Failed to generate NVGPU JSON object: 0x%04x\n", ret);
                return ret;
        }

        const char *key;
        json_t *value;
        json_object_foreach (evi_jsonobj, key, value)
        {
                if (0 != json_object_set (evidence_jsonobj_ref, key, value))
                {
                        ERROR ("Error: Failed to set JSON object key '%s'\n", key);
                        json_decref (evi_jsonobj);
                        return STATUS_NVGPU_ERROR_BASE | STATUS_JSON_SET_OBJECT_ERROR;
                }
        }
        json_decref (evi_jsonobj);

        return STATUS_OK;
}
