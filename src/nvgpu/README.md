# Intel Trust Authority C NVIDIA GPU Adapter
This is the beta version of C NVGPU Adapter for collecting GPU evidence from NVIDIA H100 enabled platform.

## System Requirement

Use <b>Ubuntu 24.04</b>. 

## Usage

Create a new C NVGPU adapter, then use the adapter to collect GPU evidence from NVGPU enabled platform.

```C Header
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
