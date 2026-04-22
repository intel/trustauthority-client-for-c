# Intel® Trust Authority Client for C NVIDIA GPU Adapter (Hopper and Blackwell)

<p style="font-size: 0.875em;">· 21 April 2026 ·</p>

This adapter collects GPU attestation evidence from NVIDIA Hopper (H100/H200) and Blackwell (B100/B200) GPUs for use with Intel Trust Domain Extensions (Intel® TDX) and Intel Trust Authority.

## System Requirement

Use <b>Ubuntu 24.04</b>.

Supported GPU architectures:
- **NVIDIA Hopper** — H100, H200 (requires CC mode enabled)
- **NVIDIA Blackwell** — B100, B200 (requires CC mode enabled)

Multiple GPUs of supported architectures are supported. All GPUs on the system must be of a supported architecture; a single unsupported device will cause an error. 

## Example usage

Create a new C NVGPU adapter, then use the adapter to collect GPU evidence from NVGPU enabled platform.

```c
#include <nvgpu_adapter.h>
evidence_adapter *adapter = NULL;
status = nvgpu_adapter_new(&adapter);
if (STATUS_OK != status)
{
    printf("Failed to create NVGPU Adapter: 0x%04x\n", status);
    return status;
}

// Evidence is collected via the evidence_builder interface.
// The resulting JSON contains an evidence_list array with one entry per GPU.
```

## JSON output schema

The adapter produces the following JSON structure in the attestation request:

```json
{
  "gpu_nonce": "<hex-encoded SHA-256 nonce>",
  "arch": "hopper",
  "evidence_list": [
    {
      "evidence": "<base64-encoded attestation report>",
      "certificate": "<base64-encoded certificate chain>",
      "firmware_version": "<VBIOS version string>"
    }
  ]
}
```

- `arch` is the lowercase architecture string of the first GPU device (`"hopper"` or `"blackwell"`).
- `evidence_list` contains one entry per GPU. All GPUs on the system must be of a supported architecture.
- `firmware_version` is omitted from an entry if the VBIOS version is not available.

To collect evidence, use the `evidence_builder` interface:

```c
// Collect NVGPU evidence via the adapter (evidence_builder calls nvgpu_get_evidence internally).
json_t *evidence_json = json_object();
if (NULL == evidence_json)
{
    printf("Failed to create evidence JSON object\n");
    return STATUS_NVGPU_ERROR_BASE | STATUS_ALLOCATION_ERROR;
}
status = adapter->get_evidence(adapter->ctx, evidence_json, nonce, NULL, 0);
if (STATUS_OK != status)
{
    printf("Failed to collect NVGPU evidence: 0x%04x\n", status);
    json_decref(evidence_json);
    return status;
}
/* Use evidence_json here. */
json_decref(evidence_json);
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../../LICENSE)
file.

## Contributing and Code of Conduct

Contributions to this project are welcome. For more information, see [Contributing](../../CONTRIBUTING.md). This project has a [Code of Conduct](../../CODE_OF_CONDUCT.md) for contributors. 