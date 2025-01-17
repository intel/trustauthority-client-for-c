# Intel® Trust Authority Client for C Intel® TDX Adapter

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

This adapter collects evidence for attestation from an Intel® Trust Domain Extensions (Intel® TDX) trust domain. This adapter works with on-premises Intel TDX servers and Google Cloud Platform confidential VM with Intel TDX. The evidence is packaged and sent to Intel® Trust Authority for attestation. 

## System Requirement

Use <b>Ubuntu 20.04</b> or later. 
The Intel TDX adapter for Intel TDX servers and GCP CVMs requires the Linux `configfs` file system to be mounted. Linux kernel 6.7 or later is required.

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

## Contributing and Code of Conduct

Contributions to this project are welcome. For more information, see [Contributing](../../../CONTRIBUTING.md). This project has a [Code of Conduct](../../CODE_OF_CONDUCT.md) for contributors. 
