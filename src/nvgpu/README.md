# Intel® Trust Authority Client for C NVIDIA H100 GPU Adapter

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

This is the limited preview version of the Intel Trust Authority Client for C NVGPU Adapter for collecting GPU evidence from a NVIDIA H100 and Intel® Trust Domain Extensions (Intel® TDX).

## System Requirement

Use <b>Ubuntu 24.04</b>. 

## Example usage

Create a new C NVGPU adapter, then use the adapter to collect GPU evidence from NVGPU enabled platform.

```c
#include <nvgpu-adapter.h> 
evidence_adapter *adapter = NULL;
status = nvgpu_adapter_new(&adapter);  
if (STATUS_OK != status)   
{  
    printf("Failed to create NVGPU Adapter: 0x%04x\n", status);  
    return status;  
}

status = nvgpu_collect_evidence(adapter->ctx, &evidence, &nonce, user_data, user_data_len);  
if (STATUS_OK != status)   
{  
    printf("Failed to collect evidence: 0x%04x\n", status);  
    return status;  
}  

```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../../LICENSE)
file.

## Contributing and Code of Conduct

Contributions to this project are welcome. For more information, see [Contributing](../../CONTRIBUTING.md). This project has a [Code of Conduct](../../CODE_OF_CONDUCT.md) for contributors. 