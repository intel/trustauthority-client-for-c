/*
 * Copyright (C) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Mock NVML implementation for unit testing of nvgpu_adapter.c.
 * Tests configure g_nvml_mock before calling adapter functions.
 */
#include "include/nvml.h"
#include <stdio.h>
#include <string.h>

/* Global mock configuration — tests set this up before each test */
mock_nvml_config_t g_nvml_mock;

void
mock_nvml_reset (void)
{
        memset (&g_nvml_mock, 0, sizeof (g_nvml_mock));
        g_nvml_mock.init_ret     = NVML_SUCCESS;
        g_nvml_mock.shutdown_ret = NVML_SUCCESS;
        g_nvml_mock.get_count_ret = NVML_SUCCESS;
        g_nvml_mock.device_count = 0;
        for (int i = 0; i < MOCK_NVML_MAX_DEVICES; i++)
        {
                g_nvml_mock.devices[i].get_handle_ret = NVML_SUCCESS;
                g_nvml_mock.devices[i].get_arch_ret   = NVML_SUCCESS;
                g_nvml_mock.devices[i].get_vbios_ret  = NVML_SUCCESS;
                g_nvml_mock.devices[i].get_report_ret = NVML_SUCCESS;
                g_nvml_mock.devices[i].get_cert_ret   = NVML_SUCCESS;
                g_nvml_mock.devices[i].arch            = NVML_DEVICE_ARCH_HOPPER;
                g_nvml_mock.devices[i].report_size     = 0;
                g_nvml_mock.devices[i].certchain_size  = 0;
        }
}

nvmlReturn_t
nvmlInit (void)
{
        return g_nvml_mock.init_ret;
}

nvmlReturn_t
nvmlShutdown (void)
{
        return g_nvml_mock.shutdown_ret;
}

nvmlReturn_t
nvmlDeviceGetCount (unsigned int *deviceCount)
{
        if (deviceCount == NULL)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.get_count_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.get_count_ret;
        }
        *deviceCount = g_nvml_mock.device_count;
        return NVML_SUCCESS;
}

/*
 * We use the device index cast to a pointer as the "handle" so that per-device
 * lookups remain simple and deterministic.
 */
nvmlReturn_t
nvmlDeviceGetHandleByIndex (unsigned int index, nvmlDevice_t *device)
{
        if (device == NULL)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (index >= g_nvml_mock.device_count || index >= MOCK_NVML_MAX_DEVICES)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.devices[index].get_handle_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.devices[index].get_handle_ret;
        }
        /* encode index in the handle pointer */
        *device = (nvmlDevice_t)(uintptr_t)(index + 1);
        return NVML_SUCCESS;
}

static unsigned int
handle_to_index (nvmlDevice_t device)
{
        return (unsigned int)((uintptr_t)device - 1);
}

nvmlReturn_t
nvmlDeviceGetArchitecture (nvmlDevice_t device, nvmlDeviceArchitecture_t *arch)
{
        if (arch == NULL)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        unsigned int idx = handle_to_index (device);
        if (idx >= MOCK_NVML_MAX_DEVICES || idx >= g_nvml_mock.device_count)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.devices[idx].get_arch_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.devices[idx].get_arch_ret;
        }
        *arch = g_nvml_mock.devices[idx].arch;
        return NVML_SUCCESS;
}

nvmlReturn_t
nvmlDeviceGetVbiosVersion (nvmlDevice_t device, char *version, unsigned int length)
{
        if (version == NULL || length == 0)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        unsigned int idx = handle_to_index (device);
        if (idx >= MOCK_NVML_MAX_DEVICES)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.devices[idx].get_vbios_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.devices[idx].get_vbios_ret;
        }
        strncpy (version, g_nvml_mock.devices[idx].vbios_version, length - 1);
        version[length - 1] = '\0';
        return NVML_SUCCESS;
}

nvmlReturn_t
nvmlDeviceGetConfComputeGpuAttestationReport (nvmlDevice_t device,
                                              nvmlConfComputeGpuAttestationReport_t *pGpuAttestation)
{
        if (pGpuAttestation == NULL)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        unsigned int idx = handle_to_index (device);
        if (idx >= MOCK_NVML_MAX_DEVICES || idx >= g_nvml_mock.device_count)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.devices[idx].get_report_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.devices[idx].get_report_ret;
        }
        if (g_nvml_mock.devices[idx].report_size > NVML_CC_GPU_CEC_REPORT_SIZE)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        memcpy (pGpuAttestation->attestationReport,
                g_nvml_mock.devices[idx].report_data,
                g_nvml_mock.devices[idx].report_size);
        pGpuAttestation->attestationReportSize = g_nvml_mock.devices[idx].report_size;
        return NVML_SUCCESS;
}

nvmlReturn_t
nvmlDeviceGetConfComputeGpuCertificate (nvmlDevice_t device,
                                        nvmlConfComputeGpuCertificate_t *pCertChain)
{
        if (pCertChain == NULL)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        unsigned int idx = handle_to_index (device);
        if (idx >= MOCK_NVML_MAX_DEVICES || idx >= g_nvml_mock.device_count)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        if (g_nvml_mock.devices[idx].get_cert_ret != NVML_SUCCESS)
        {
                return g_nvml_mock.devices[idx].get_cert_ret;
        }
        if (g_nvml_mock.devices[idx].certchain_size > NVML_CC_GPU_CERT_CHAIN_SIZE)
        {
                return NVML_ERROR_INVALID_ARGUMENT;
        }
        memcpy (pCertChain->attestationCertChain,
                g_nvml_mock.devices[idx].certchain_data,
                g_nvml_mock.devices[idx].certchain_size);
        pCertChain->attestationCertChainSize = g_nvml_mock.devices[idx].certchain_size;
        return NVML_SUCCESS;
}

const char *
nvmlErrorString (nvmlReturn_t result)
{
        switch (result)
        {
        case NVML_SUCCESS:              return "Success";
        case NVML_ERROR_UNINITIALIZED:  return "Driver not initialized";
        case NVML_ERROR_INVALID_ARGUMENT: return "Invalid argument";
        case NVML_ERROR_NOT_SUPPORTED:  return "Not supported";
        case NVML_ERROR_NO_PERMISSION:  return "No permission";
        case NVML_ERROR_MEMORY:         return "Memory allocation failed";
        default:                        return "Unknown error";
        }
}
