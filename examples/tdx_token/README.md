# TDX Token Example
The TDX Token example is a C program that uses the Intel Trust Authority Attestation Client libraries
to fetch token from Intel Trust Authority. The program suppose to run inside a TD.  When run, 
it collects a quote from the TD and sends it to Intel Trust Authority to retrieve a token.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │        TDX Token         │      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│   INTEL TRUST  │
│    │    │  libtrustauthotiy_tdx.so │      │    │                │   AUTHORITY    │
│    │    └──────────────────────────┘      │    │                │   SERVER       │
│    │                                      │    │                └────────────────┘
│    │    ┌──────────────────────────┐      │    │
│    │    │lib_trustauthotiy_        |      |    |
|    │    │    connector.so          |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │ libtrustauthotiy_          |    |    |
|    |    | token_provider.so          │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │ libtrustauthotiy_          |    |    |
|    |    |  token_verifier.so         │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  TD VM                         │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the TDX Token while running within
a docker container.  The TDX Token example can also be run directly inside a TD vm (provided
the appropriate dependencies like DCAP have been installed). 

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *pre-production* TDX host with the TDX kernel and TD installed.
- The TDX host must be able to generate quotes.
- A running instance of Intel Trust Authority (see versions above).

## Build Instructions
- Build the TDX Token docker image in release/debug mode:
```shell
  - To Build in release mode:  
	make tdx_token_docker
  - To Build in debug mode:  
	make DEBUG=1 tdx_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/tdx_token:v1.3.0`.

**_NOTE:_** If you are building for Azure, use below commands:
```shell
  - To Build in release mode:
	make azure_tdx_token_docker
  - To Build in debug mode:
	make DEBUG=1 azure_tdx_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/azure_tdx_token:v1.3.0`.

## Deployment Instructions
- The docker image must be present inside the TD vm.  For example, it can be exported/copied 
from a build machine as follows...
```shell
#Save the tdx_token Docker image into trust_authority.tdx_token.tar.gz
docker save taas/tdx_token:v0.1.0 > trust_authority.tdx_token.tar.gz
#scp trust_authority.tdx_token.tar.gz to the TD VM.
#On the TD VM load/import trust_authority.tdx_token.tar.gz docker image using below command
docker load -i trust_authority.tdx_token.tar.gz
``` 

## Running the Sample
Running the sample requires the following steps...
1. Collect the measurements from the example application.
2. Creating an Intel Trust Authority policy that will be evaluated during token creation.
3. Running the TDX Token application via docker in a TD VM.

### Example Environment Variables
- The following table lists the environment variables used in tdx_token.env
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
    

### Run the example...
- Use docker to run the TDX Token example...
    ```
    cat <<EOF | tee tdx_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
    TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
    EOF
    sudo docker run -it --rm --privileged --network host -v /sys/kernel/config:/sys/kernel/config  --env-file tdx_token.env taas/intel_tdx_token:v1.3.0
    ```

- Use docker to run the Azure TDX Token example...
    ```
    cat <<EOF | tee tdx_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
    TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
    EOF

    sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --env-file tdx_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_tdx_token:v1.3.0
    ```

### Output when TDX example is run...
- When successful, the token and other information will be displayed...
