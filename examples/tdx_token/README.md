# Intel® TDX Attestation Token Example

<p style="font-size: 0.875em;">· 07 May 2025 ·</p>

The Intel® Trust Domain Extensions (Intel® TDX) attestation token example is a C program that uses the Intel® Trust Authority Attestation Client libraries to collect evidence from the TEE and then request a token from Intel Trust Authority. If the token request is successful, the example prints the contents of the token and other information to the screen. 

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │      Intel TDX Token     │      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│   INTEL TRUST  │
│    │    │ libtrustauthority_tdx.so │      │    │                │   AUTHORITY    │
│    │    └──────────────────────────┘      │    │                │   SERVER       │
│    │                                      │    │                └────────────────┘
│    │    ┌──────────────────────────┐      │    │
│    │    │ lib_trustauthority_      |      |    |
|    │    │ connector.so             |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │ libtrustauthority_         |    |    |
|    |    | evidence_builder.so        │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │ libtrustauthority_         |    |    |
|    |    | token_verifier.so          │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  Intel TDX VM                  │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the Intel TDX Token example while running within a docker container. The Intel TDX Token example can also be run directly inside a TD VM.

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *pre-production* TDX host with the TDX kernel and TD installed.
- The TDX host must be able to generate quotes.
- A running instance of Intel Trust Authority (see versions above).


## Build and run the example

Build the Intel TDX example Docker image. You can build the image in debug or release mode under `trustauthority-client` home folder. 

1. For on-premises Intel TDX server and GCP CVMs with Intel TDX, use the following commands.
  1. To build the image in release mode:
  ```shell
    make tdx_token_docker
  ```
  1. To build the image in debug mode:
  ```shell
    make DEBUG=1 tdx_token_docker
  ```
  1. When successfully built, running `docker image ls -a` includes `taas/tdx_token:v1.3.0`.

2. If you are building for Azure, use following commands.
  1. Release mode:
  ```shell
    make azure_tdx_token_docker
  ```
  1. Debug mode
  ```shell
    make DEBUG=1 azure_tdx_token_docker
  ```
  1. When successfully built, running `docker image ls -a` includes `taas/azure_tdx_token:v1.3.0`.


3. The docker image must be present inside the TD vm.  For example, it can be exported/copied from a build machine as follows.
  ```shell
  #Save the tdx_token Docker image into trust_authority.tdx_token.tar.gz
  docker save taas/tdx_token:v1.3.0 > trust_authority.tdx_token.tar.gz
  #scp trust_authority.tdx_token.tar.gz to the TD VM.
  #On the TD VM load/import trust_authority.tdx_token.tar.gz docker image using below command
  docker load -i trust_authority.tdx_token.tar.gz
  ``` 

The example relies on an environment file for information such as the API key and Intel Trust Authority base URL. The following table lists the environment variables used in `tdx_token.env`. Most of the variables are optional except the first four, which are required.

|Variable|Description|
|:--------|:-----------|
|TRUSTAUTHORITY_API_KEY|The Intel Trust Authority API key.|
|TRUSTAUTHORITY_POLICY_ID|The policy id created using Intel Trust Authority portal.|
|TRUSTAUTHORITY_API_URL|The Intel Trust Authority API URL.| 
|TRUSTAUTHORITY_BASE_URL|The base url of Intel Trust Authority certificate management authority to download certificate to verify token in Azure. (ex. "https://portal.trustauthority.intel.com")|
|REQUEST_ID|An optional parameter to trace the request.|
|TOKEN_SIGNING_ALG|An optional parameter to specify token signing algorithm, supported algorithms are RS256, PS384.|
|POLICY_MUST_MATCH|An optional boolean parameter to enforce policies match during attestation, supported values are true/false.|
|RETRY_WAIT_TIME|Wait time between retries. Default value is 2 seconds.|
|RETRY_MAX|Maximum number of retries. Default value is 2 seconds.|
    
4. Create the tdx_token.env file. Replace the values in <> with your values. If you are in the EU, the values for API_URL and BASE_URL are different than shown here.

```shell
  cat <<EOF | tee tdx_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL=https://api.trustauthority.intel.com
    TRUSTAUTHORITY_BASE_URL=https://portal.trustauthority.intel.com
    EOF
```


5: Use docker to run the Intel TDX example. Use the command that matches your Intel TDX platform.
  1. On-prem servers and GCP CVMs with Intel TDX:
  ```shell
    sudo docker run -it --rm --privileged --network host -v /sys/kernel/config:/sys/kernel/config  --env-file tdx_token.env taas/intel_tdx_token:v1.3.0
  ```
  1. Azure CVM with Intel TDX:
  ```shell
    sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --env-file tdx_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_tdx_token:v1.3.0
  ```
If the request for an attestation token is successful, the example prints the contents of the token and other information to the screen.
