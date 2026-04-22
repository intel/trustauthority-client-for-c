/*
 * Copyright (C) 2025-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Unit tests for nvgpu_adapter.c mGPU changes.
 * Tests use the mock NVML library (tests/mock_nvml/) to avoid real GPU hardware.
 */
#include <gtest/gtest.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
#include <nvgpu_adapter.h>
#include <types.h>
#include "mock_nvml/include/nvml.h"
}

/* ---- Helpers ---- */

static void
fill_device (int idx, nvmlDeviceArchitecture_t arch,
             const char *vbios,
             const uint8_t *report, unsigned int report_sz,
             const uint8_t *cert,   unsigned int cert_sz)
{
        g_nvml_mock.devices[idx].arch         = arch;
        g_nvml_mock.devices[idx].report_size  = report_sz;
        g_nvml_mock.devices[idx].certchain_size = cert_sz;
        assert(report_sz <= NVML_CC_GPU_CEC_REPORT_SIZE);
        assert(cert_sz <= NVML_CC_GPU_CERT_CHAIN_SIZE);
        memcpy (g_nvml_mock.devices[idx].report_data, report, report_sz);
        memcpy (g_nvml_mock.devices[idx].certchain_data, cert, cert_sz);
        memset (g_nvml_mock.devices[idx].vbios_version, 0,
                NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE);
        if (vbios)
        {
                strncpy (g_nvml_mock.devices[idx].vbios_version, vbios,
                         NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE - 1);
                g_nvml_mock.devices[idx].vbios_version[NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE - 1] = '\0';
        }
}

/* Decode base64 string → raw bytes. Returns number of decoded bytes, -1 on error. */
static int
base64_decode (const char *b64, uint8_t *out, size_t out_sz)
{
        BIO *bmem = BIO_new_mem_buf (b64, (int)strlen (b64));
        BIO *b64bio = BIO_new (BIO_f_base64 ());
        BIO_set_flags (b64bio, BIO_FLAGS_BASE64_NO_NL);
        bmem = BIO_push (b64bio, bmem);
        int len = BIO_read (bmem, out, (int)out_sz);
        BIO_free_all (bmem);
        return len;
}

/* ---- Test fixture ---- */

class NvgpuAdapterTest : public ::testing::Test
{
protected:
        void SetUp () override { mock_nvml_reset (); }
};

/* ================================================================
 * nvgpu_adapter_new / nvgpu_adapter_free
 * ================================================================ */

TEST_F (NvgpuAdapterTest, AdapterNew_Success)
{
        evidence_adapter *adapter = nullptr;
        int result = nvgpu_adapter_new (&adapter);
        ASSERT_EQ (result, STATUS_OK);
        ASSERT_NE (adapter, nullptr);
        ASSERT_NE (adapter->ctx, nullptr);
        ASSERT_EQ (adapter->collect_evidence, nullptr);   /* GPU uses get_evidence path */
        ASSERT_EQ (adapter->get_evidence, nvgpu_get_evidence);
        nvgpu_adapter_free (adapter);
}

TEST_F (NvgpuAdapterTest, AdapterNew_NullAdapter)
{
        int result = nvgpu_adapter_new (nullptr);
        ASSERT_EQ (result, STATUS_NVGPU_ERROR_BASE | STATUS_NULL_ADAPTER);
}

TEST_F (NvgpuAdapterTest, AdapterFree_NullAdapter)
{
        /* should not crash */
        int result = nvgpu_adapter_free (nullptr);
        ASSERT_EQ (result, STATUS_OK);
}

TEST_F (NvgpuAdapterTest, EvidenceIdentifier)
{
        ASSERT_STREQ (nvgpu_get_evidence_identifier (), "nvgpu");
}

/* ================================================================
 * Zero devices → error
 * ================================================================ */

TEST_F (NvgpuAdapterTest, ZeroDevices_Error)
{
        g_nvml_mock.device_count = 0;

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        int result = nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0);
        EXPECT_NE (result, STATUS_OK);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Single Hopper GPU — happy path
 * ================================================================ */

TEST_F (NvgpuAdapterTest, SingleHopperGPU_EvidenceList)
{
        const uint8_t report[]  = { 0x01, 0x02, 0x03, 0x04 };
        const uint8_t cert[]    = { 0xAA, 0xBB, 0xCC };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "96.00.9F.00.01",
                     report, sizeof (report), cert, sizeof (cert));

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        int result = nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0);
        ASSERT_EQ (result, STATUS_OK);

        /* arch must be "hopper" */
        json_t *arch_j = json_object_get (ev, "arch");
        ASSERT_NE (arch_j, nullptr);
        EXPECT_STREQ (json_string_value (arch_j), "hopper");

        /* evidence_list must be an array with 1 entry */
        json_t *elist = json_object_get (ev, "evidence_list");
        ASSERT_NE (elist, nullptr);
        ASSERT_TRUE (json_is_array (elist));
        EXPECT_EQ (json_array_size (elist), (size_t)1);

        json_t *entry = json_array_get (elist, 0);
        ASSERT_NE (entry, nullptr);

        /* evidence field must be valid base64 that decodes to the original report */
        json_t *evi_j = json_object_get (entry, "evidence");
        ASSERT_NE (evi_j, nullptr);
        const char *b64_evi = json_string_value (evi_j);
        uint8_t decoded[64];
        int decoded_len = base64_decode (b64_evi, decoded, sizeof (decoded));
        ASSERT_EQ (decoded_len, (int)sizeof (report));
        EXPECT_EQ (memcmp (decoded, report, sizeof (report)), 0);

        /* certificate field must be valid base64 that decodes to the original cert */
        json_t *cert_j = json_object_get (entry, "certificate");
        ASSERT_NE (cert_j, nullptr);
        int cert_decoded_len = base64_decode (json_string_value (cert_j), decoded, sizeof (decoded));
        ASSERT_EQ (cert_decoded_len, (int)sizeof (cert));
        EXPECT_EQ (memcmp (decoded, cert, sizeof (cert)), 0);

        /* firmware_version must be present */
        json_t *fw_j = json_object_get (entry, "firmware_version");
        ASSERT_NE (fw_j, nullptr);
        EXPECT_STREQ (json_string_value (fw_j), "96.00.9F.00.01");

        /* old flat fields must NOT be present */
        EXPECT_EQ (json_object_get (ev, "evidence"), nullptr);
        EXPECT_EQ (json_object_get (ev, "certificate"), nullptr);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Single Blackwell GPU — happy path
 * ================================================================ */

TEST_F (NvgpuAdapterTest, SingleBlackwellGPU_ArchString)
{
        const uint8_t report[] = { 0x10, 0x20 };
        const uint8_t cert[]   = { 0x30, 0x40 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_BLACKWELL, "100.00.01.00.00",
                     report, sizeof (report), cert, sizeof (cert));

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0), STATUS_OK);

        json_t *arch_j = json_object_get (ev, "arch");
        ASSERT_NE (arch_j, nullptr);
        EXPECT_STREQ (json_string_value (arch_j), "blackwell");

        json_t *elist = json_object_get (ev, "evidence_list");
        ASSERT_TRUE (json_is_array (elist));
        EXPECT_EQ (json_array_size (elist), (size_t)1);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Two Hopper GPUs — evidence_list has two entries
 * ================================================================ */

TEST_F (NvgpuAdapterTest, TwoHopperGPUs_EvidenceListHasTwoEntries)
{
        const uint8_t report0[] = { 0x01, 0x02 };
        const uint8_t cert0[]   = { 0x03, 0x04 };
        const uint8_t report1[] = { 0x05, 0x06, 0x07 };
        const uint8_t cert1[]   = { 0x08, 0x09 };

        g_nvml_mock.device_count = 2;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "96.00.9F.00.01",
                     report0, sizeof (report0), cert0, sizeof (cert0));
        fill_device (1, NVML_DEVICE_ARCH_HOPPER, "96.00.9F.00.02",
                     report1, sizeof (report1), cert1, sizeof (cert1));

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0), STATUS_OK);

        json_t *elist = json_object_get (ev, "evidence_list");
        ASSERT_TRUE (json_is_array (elist));
        EXPECT_EQ (json_array_size (elist), (size_t)2);

        /* Verify per-device data */
        for (size_t i = 0; i < 2; i++)
        {
                json_t *entry = json_array_get (elist, i);
                ASSERT_NE (entry, nullptr);
                EXPECT_NE (json_object_get (entry, "evidence"),    nullptr);
                EXPECT_NE (json_object_get (entry, "certificate"), nullptr);
        }

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * arch from first device used at top level (mixed Hopper + Blackwell)
 * ================================================================ */

TEST_F (NvgpuAdapterTest, MixedArch_TopLevelArchFromFirstDevice)
{
        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };

        g_nvml_mock.device_count = 2;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER,    "fw1", report, 1, cert, 1);
        fill_device (1, NVML_DEVICE_ARCH_BLACKWELL,  "fw2", report, 1, cert, 1);

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0), STATUS_OK);

        json_t *arch_j = json_object_get (ev, "arch");
        ASSERT_NE (arch_j, nullptr);
        EXPECT_STREQ (json_string_value (arch_j), "hopper");

        EXPECT_EQ (json_array_size (json_object_get (ev, "evidence_list")), (size_t)2);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Unsupported architecture → error
 * ================================================================ */

TEST_F (NvgpuAdapterTest, UnsupportedArch_Ampere_Error)
{
        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_AMPERE, "", report, 1, cert, 1);

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        int result = nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0);
        EXPECT_NE (result, STATUS_OK);

        /* No evidence_list should be present in the output */
        EXPECT_EQ (json_object_get (ev, "evidence_list"), nullptr);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Evidence encoding: base64(raw bytes), NOT base64(hex(raw bytes))
 * ================================================================ */

TEST_F (NvgpuAdapterTest, EvidenceEncoding_Base64Only_NoHexLayer)
{
        /* Use a known byte sequence that would produce different base64 depending
           on whether hex-encoding is applied first */
        const uint8_t report[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        const uint8_t cert[]   = { 0x00 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "", report, sizeof (report), cert, sizeof (cert));

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0), STATUS_OK);

        json_t *elist = json_object_get (ev, "evidence_list");
        const char *b64 = json_string_value (json_object_get (json_array_get (elist, 0), "evidence"));
        ASSERT_NE (b64, nullptr);

        /* Decode and check raw bytes match exactly */
        uint8_t decoded[64];
        int decoded_len = base64_decode (b64, decoded, sizeof (decoded));
        ASSERT_EQ (decoded_len, (int)sizeof (report));
        EXPECT_EQ (memcmp (decoded, report, sizeof (report)), 0);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * firmware_version absent when NVML returns an error for it
 * ================================================================ */

TEST_F (NvgpuAdapterTest, FirmwareVersionAbsent_WhenNvmlFails)
{
        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "", report, 1, cert, 1);
        /* Make VBIOS lookup fail — adapter should proceed without firmware_version */
        g_nvml_mock.devices[0].get_vbios_ret = NVML_ERROR_NOT_SUPPORTED;

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0), STATUS_OK);

        json_t *entry = json_array_get (json_object_get (ev, "evidence_list"), 0);
        /* firmware_version should be absent (empty string → not emitted) */
        EXPECT_EQ (json_object_get (entry, "firmware_version"), nullptr);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * Nonce paths: gpu_nonce vs verifier_nonce
 * ================================================================ */

TEST_F (NvgpuAdapterTest, NoncePath_GpuNonce_WhenNoVerifierNonce)
{
        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "fw", report, 1, cert, 1);

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        /* Pass a nonce with empty val/iat → should use gpu_nonce */
        nonce n = {};
        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, &n, nullptr, 0), STATUS_OK);

        EXPECT_NE (json_object_get (ev, "gpu_nonce"),      nullptr);
        EXPECT_EQ (json_object_get (ev, "verifier_nonce"), nullptr);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

TEST_F (NvgpuAdapterTest, NoncePath_VerifierNonce_WhenValAndIatProvided)
{
        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };

        g_nvml_mock.device_count = 1;
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "fw", report, 1, cert, 1);

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        /* Provide val + iat + signature so the verifier_nonce path is taken */
        const char val_str[] = "test_nonce_val";
        const char iat_str[] = "2026-01-01T00:00:00Z";
        const char sig_str[] = "dGVzdF9zaWduYXR1cmU=";
        nonce n = {};
        n.val          = (uint8_t *)val_str;
        n.val_len      = (uint32_t)strlen (val_str);
        n.iat          = (uint8_t *)iat_str;
        n.iat_len      = (uint32_t)strlen (iat_str);
        n.signature    = (uint8_t *)sig_str;
        n.signature_len = (uint32_t)strlen (sig_str);

        json_t *ev = json_object ();
        ASSERT_EQ (nvgpu_get_evidence (adapter->ctx, ev, &n, nullptr, 0), STATUS_OK);

        EXPECT_NE (json_object_get (ev, "verifier_nonce"), nullptr);
        EXPECT_EQ (json_object_get (ev, "gpu_nonce"),      nullptr);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * NVML init failure → error propagated
 * ================================================================ */

TEST_F (NvgpuAdapterTest, NvmlInitFailure_PropagatesError)
{
        g_nvml_mock.init_ret = NVML_ERROR_UNINITIALIZED;
        g_nvml_mock.device_count = 1;

        const uint8_t report[] = { 0x01 };
        const uint8_t cert[]   = { 0x02 };
        fill_device (0, NVML_DEVICE_ARCH_HOPPER, "", report, 1, cert, 1);

        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);

        json_t *ev = json_object ();
        int result = nvgpu_get_evidence (adapter->ctx, ev, nullptr, nullptr, 0);
        EXPECT_NE (result, STATUS_OK);

        json_decref (ev);
        nvgpu_adapter_free (adapter);
}

/* ================================================================
 * get_evidence with null ctx or null json object → error
 * ================================================================ */

TEST_F (NvgpuAdapterTest, GetEvidence_NullCtx_Error)
{
        json_t *ev = json_object ();
        int result = nvgpu_get_evidence (nullptr, ev, nullptr, nullptr, 0);
        EXPECT_EQ (result, STATUS_INVALID_PARAMETER);
        json_decref (ev);
}

TEST_F (NvgpuAdapterTest, GetEvidence_NullJsonObj_Error)
{
        evidence_adapter *adapter = nullptr;
        ASSERT_EQ (nvgpu_adapter_new (&adapter), STATUS_OK);
        int result = nvgpu_get_evidence (adapter->ctx, nullptr, nullptr, nullptr, 0);
        EXPECT_EQ (result, STATUS_INVALID_PARAMETER);
        nvgpu_adapter_free (adapter);
}
