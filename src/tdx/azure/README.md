# Intel Trust Authority C TDX Adapter
This is the beta version of C TDX Adapter for collecting Quote from TDX enabled platform.

This library leverages the TPM2 TSS library (specifically TSS2 ESYS APIs) and tpm2-tools for Quote generation. TPM2 TSS library: [https://github.com/tpm2-software/tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

The TPM2 TSS library needs to be installed using [installation steps](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md) in the build environment to build the adapter.

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Tools requirement

Please install tpm2-tools before using the library to generate quote.

```
apt-get install tpm2-tools=4.1.1-1ubuntu0.20.04.1
```

## Usage

Create a new Azure TDX adapter, then use the adapter to collect quote from Azure TDX enabled platform.

```C Header
#include <tdx_adapter.h>

status = azure_tdx_adapter_new(&adapter);
if (STATUS_OK != result)  
{  
    printf("Failed to create TDX Adapter: 0x%04x\n", status);
    return status;  
}   

status = tdx_collect_evidence_azure(adapter->ctx, &evidence, &nonce, user_data, user_data_len);
if (status != STATUS_OK)  
{  
    printf("Failed to collect TDX evidence: 0x%04x\n", status); 
    return status;  
}
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../../../LICENSE)
file.
