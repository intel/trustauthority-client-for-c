# Intel® Trust Authority Client for C Intel TDX Adapter for Azure

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

This is the Intel® Trust Authority Client for C adapter for collecting evidence from an Azure confidential virtual machine (CVM) with Intel® Trust Domain Extensions (Intel® TDX) technology.

This library requires the TPM2 TSS library (specifically TSS2 ESYS APIs) and tpm2-tools for quote generation. TPM2 TSS library: [https://github.com/tpm2-software/tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

The TPM2 TSS library needs to be installed using [installation steps](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md) in the build environment to build the adapter.

## System Requirement

Azure provides customized OS images for CVMs. Use the confidential compute image for Ubuntu 20.04.

## Tools requirement

You must install **tpm2-tools** on the CVM before using the library to generate a quote. Use the following command to install tpm2-tools for Ubuntu 20.04.

```shell
apt-get install tpm2-tools=4.1.1-1ubuntu0.20.04.1
```

## Usage example

Create a new Azure CVM Intel TDX adapter, and then use the adapter to collect a quote from the CVM.

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

## Contributing and Code of Conduct

Contributions to this project are welcome. For more information, see [Contributing](../../../CONTRIBUTING.md). This project has a [Code of Conduct](../../CODE_OF_CONDUCT.md) for contributors. 