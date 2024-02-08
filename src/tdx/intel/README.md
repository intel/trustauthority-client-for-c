# Intel Trust Authority C TDX Adapter
This is the beta version of C TDX Adapter for collecting Quote from TDX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Usage

Create a new C TDX adapter, then use the adapter to collect quote from TDX enabled platform.

```C Header
#include <tdx.h>  

status = tdx_adapter_new(&adapter);  
if (STATUS_OK != result)  
{  
    printf("Failed to create TDX Adapter: 0x%04x\n", status);  
    return status;  
}   

status = tdx_collect_evidence(adapter->ctx, &evidence, &nonce, user_data, user_data_len);  
if (status != STATUS_OK)  
{  
    printf("Failed to collect evidence: 0x%04x\n", status);  
    return status;  
}
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../../../LICENSE)
file.
