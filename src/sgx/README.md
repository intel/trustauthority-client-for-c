# Intel Trust Authority C SGX Adapter
This is the beta version of C SGX Adapter for collecting Quote from SGX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Usage

Create a new C SGX adapter, then use the adapter to collect quote from SGX enabled platform.

```C Header
#include <sgx-adapter.h> 
evidence_adapter *adapter = NULL;
status = sgx_adapter_new(&adapter, eid, enclave_create_report);  
if (STATUS_OK != status)   
{  
    printf("Failed to create SGX Adapter: 0x%04x\n", status);  
    return status;  
}

status = sgx_collect_evidence(adapter->ctx, &evidence, &nonce, user_data, user_data_len);  
if (STATUS_OK != status)   
{  
    printf("Failed to collect evidence: 0x%04x\n", status);  
    return status;  
}  

```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../../LICENSE)
file.
