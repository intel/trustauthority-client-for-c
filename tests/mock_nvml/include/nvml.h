/*
 * Copyright (C) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Minimal mock NVML header for unit testing of nvgpu_adapter.c.
 * Only the types and constants actually used by nvgpu_adapter.c are defined.
 */
#ifndef MOCK_NVML_H_
#define MOCK_NVML_H_

#include <stdint.h>
#include <string.h>

/* ---- Return codes ---- */
typedef enum nvmlReturn_enum
{
        NVML_SUCCESS = 0,
        NVML_ERROR_UNINITIALIZED = 1,
        NVML_ERROR_INVALID_ARGUMENT = 2,
        NVML_ERROR_NOT_SUPPORTED = 3,
        NVML_ERROR_NO_PERMISSION = 4,
        NVML_ERROR_ALREADY_INITIALIZED = 5,
        NVML_ERROR_NOT_FOUND = 6,
        NVML_ERROR_INSUFFICIENT_SIZE = 7,
        NVML_ERROR_MEMORY = 8,
        NVML_ERROR_UNKNOWN = 999,
} nvmlReturn_t;

/* ---- Device handle ---- */
typedef void *nvmlDevice_t;

/* ---- Architecture enum ---- */
typedef enum nvmlDeviceArchitecture_enum
{
        NVML_DEVICE_ARCH_KEPLER    = 2,
        NVML_DEVICE_ARCH_MAXWELL   = 3,
        NVML_DEVICE_ARCH_PASCAL    = 4,
        NVML_DEVICE_ARCH_VOLTA     = 5,
        NVML_DEVICE_ARCH_TURING    = 6,
        NVML_DEVICE_ARCH_AMPERE    = 7,
        NVML_DEVICE_ARCH_ADA       = 8,
        NVML_DEVICE_ARCH_HOPPER    = 9,
        NVML_DEVICE_ARCH_BLACKWELL = 10,
        NVML_DEVICE_ARCH_UNKNOWN   = 0xffffffff,
} nvmlDeviceArchitecture_t;

/* ---- Buffer / struct sizes ---- */
#define NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE  32
#define NVML_CC_GPU_CEC_NONCE_SIZE      32
#define NVML_CC_GPU_CEC_REPORT_SIZE     512
#define NVML_CC_GPU_CERT_CHAIN_SIZE     512

/* ---- CC attestation structs ---- */
typedef struct nvmlConfComputeGpuAttestationReport_st
{
        unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
        unsigned char attestationReport[NVML_CC_GPU_CEC_REPORT_SIZE];
        unsigned int  attestationReportSize;
} nvmlConfComputeGpuAttestationReport_t;

typedef struct nvmlConfComputeGpuCertificate_st
{
        unsigned char attestationCertChain[NVML_CC_GPU_CERT_CHAIN_SIZE];
        unsigned int  attestationCertChainSize;
} nvmlConfComputeGpuCertificate_t;

/* ---- API functions (implemented in mock_nvml.c) ---- */
#ifdef __cplusplus
extern "C" {
#endif

nvmlReturn_t nvmlInit(void);
nvmlReturn_t nvmlShutdown(void);
nvmlReturn_t nvmlDeviceGetCount(unsigned int *deviceCount);
nvmlReturn_t nvmlDeviceGetHandleByIndex(unsigned int index, nvmlDevice_t *device);
nvmlReturn_t nvmlDeviceGetArchitecture(nvmlDevice_t device, nvmlDeviceArchitecture_t *arch);
nvmlReturn_t nvmlDeviceGetVbiosVersion(nvmlDevice_t device, char *version, unsigned int length);
nvmlReturn_t nvmlDeviceGetConfComputeGpuAttestationReport(nvmlDevice_t device,
                                                          nvmlConfComputeGpuAttestationReport_t *pGpuAttestation);
nvmlReturn_t nvmlDeviceGetConfComputeGpuCertificate(nvmlDevice_t device,
                                                    nvmlConfComputeGpuCertificate_t *pCertChain);
const char  *nvmlErrorString(nvmlReturn_t result);

/* ---- Mock configuration API ---- */

#define MOCK_NVML_MAX_DEVICES 8

typedef struct mock_nvml_device_config
{
        nvmlReturn_t          get_handle_ret;
        nvmlDeviceArchitecture_t arch;
        nvmlReturn_t          get_arch_ret;
        char                  vbios_version[NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE];
        nvmlReturn_t          get_vbios_ret;
        unsigned char         report_data[NVML_CC_GPU_CEC_REPORT_SIZE];
        unsigned int          report_size;
        nvmlReturn_t          get_report_ret;
        unsigned char         certchain_data[NVML_CC_GPU_CERT_CHAIN_SIZE];
        unsigned int          certchain_size;
        nvmlReturn_t          get_cert_ret;
} mock_nvml_device_config_t;

typedef struct mock_nvml_config
{
        nvmlReturn_t              init_ret;
        nvmlReturn_t              shutdown_ret;
        unsigned int              device_count;
        nvmlReturn_t              get_count_ret;
        mock_nvml_device_config_t devices[MOCK_NVML_MAX_DEVICES];
} mock_nvml_config_t;

/* Global config that tests populate before calling adapter functions */
extern mock_nvml_config_t g_nvml_mock;

/* Reset g_nvml_mock to safe defaults (all NVML_SUCCESS, 0 devices) */
void mock_nvml_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_NVML_H_ */
