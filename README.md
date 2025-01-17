# Intel® Trust Authority Client for C

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

Intel® Trust Authority Client for C provides a set of C libraries for attesting different TEEs with Intel Trust Authority. Users can link the C libraries within their application to collect evidence for attestation, request an attestation token from Intel Trust Authority, and perform other functions. 

The Client for C comprises a main library that encapsulates the Intel Trust Authority REST API, called the _connector_, and a collection of platform _adapters_. Adapters handle the low-level functionality needed to collect evidence for attestation from a TEE or platform. 

The C connector can be used alone by a relying party, for example, to validate a token, or to request a token in Background-Check mode using evidence collected by the attester. The connector, used alone, does not need to run in a TEE and it doesn't need an adapter.

Attesting parties require both the connector and one or more adapters. Attesters can operate in either Passport or Background-Check mode. The Client for C can also be used to collect measurements from a reference configuration for use in appraisal policies.

Currently, the following platforms are supported in General Availability status:

- Intel® Software Guard Extensions (Intel® SGX) enclaves use the [**Intel SGX**](./src/sgx/README.md) adapter.
- Intel® Trust Domain Extensions (Intel® TDX). There are two adapters for Intel TDX:
    1. Use the [**Intel**](./src/tdx/intel/README.md) adapter for Intel TDX-enabled hardware running Linux with the 'configfs' filesystem(Linux kernel 6.7 or later), which includes on-premises servers and GCP confidential VMs with Intel TDX.
    2. Use the [**Azure**](./src/tdx/azure/README.md) adapter for Azure confidential VMs with Intel TDX and vTPM.

For more information about client integration with Intel Trust Authority, see the primary online documentation.

## What's new in this release?

The Client for C now includes pre-release ("beta") adapters for the following platforms. Details of implementation and usage  may change before general availability.

- Google Cloud Platform (GCP) confidential VMs with Intel TDX.
- NVIDIA H100\* GPU and Intel TDX.
- Support for TPMs and Azure vTPM.
- AMD SEV-SNP\* on Azure and GCP. 

AMD SEV-SNP is supported in limited preview status in the pilot environment only. For preview access, please contact your Intel sales representative. 

New [**example applications**](./examples/) were added for the pre-release adapters, and existing examples for Intel SGX and Intel TDX were updated to work with the latest adapter version.  


## System Requirement

Use Ubuntu 20.04 or later for most adapters. The NVGPU adapter requires Ubuntu 24.04. 

Some platforms have additional requirements; see the adapter's README for details. 

## Installation

Follow the build instructions of library from [builds.md](./docs/builds.md) 

Installation steps:
1. Copy the libraries built from above steps to application path and export them to LD_LIBRARY_PATH.
2. LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path to libraries generated.>
3. export LD_LIBRARY_PATH

### Unit tests

For details of building and running the unit tests, see the [Unit test build instructions](./docs/build_ut_tests.md).

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.

## Contributing and Code of Conduct

Contributions to this project are welcome. For more information, see [Contributing](CONTRIBUTING.md). This project has a [Code of Conduct](CODE_OF_CONDUCT.md) for contributors. 

<br><br>

---
**\*** Other names and brands may be claimed as the property of others.