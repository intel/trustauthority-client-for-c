# SGX Token Example
The SGX Token example is a C program that uses the Intel Trust Authority Attestation Client libraries
to fetch token from Intel Trust Authority. The program contains an example SGX enclave. When run, 
it collects quote from the enclave and sends it to Intel Trust Authority to retrieve a token.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │        SGX Token         │      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│ INTEL TRUST    |
│    │    │     enclave.signed.so    │      │    │                │ AUTHORITY      |
│    │    └──────────────────────────┘      │    │                │ CLIENT         |
│    │                                      │    │                └────────────────┘   
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |libtrustauthotiy_sgx.so   |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      │    │
│    │    │      libtrustauthotiy_   |      |    |
|    |    |      connector.so        │      │    │
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │   libtrustauthotiy_        |    |    |
|    |    |   token_provider.so        │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │  libtrustauthotiy_         |    |    |
|    |    |  token_verifier.so         │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  SGX Host                      │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the SGX Token while running within
a docker container. The SGX Token example can also be run directly on a SGX host (provided
the appropriate dependencies like DCAP have been installed).

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *production* SGX host with the SGX driver and Docker installed.
- The SGX host must be able to generate quotes.
- A running instance of Intel Trust Authority.

## Build Instructions
- Build  SGX Token docker image in release/debug mode:
```shell
  - To Build in release mode:  
	make sgx_token_docker
  - To Build in debug mode:  
	make DEBUG=1 sgx_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/sgx_token:v1.2.0`.

## Deployment Instructions

- The docker image must be present on the SGX host.  For example, it can be exported/copied from a build machine as follows...
```shell
#Save the sgx_token Docker image into trust_authority.sgx_token.tar.gz
docker save taas/sgx_token:v1.2.0 > trust_authority.sgx_token.tar.gz
#scp trust_authority.sgx_token.tar.gz to the SGX host.
#On the SGX host load/import trust_authority.sgx_token.tar.gz docker image using below command
docker load -i trust_authority.sgx_token.tar.gz
```

## Running the Sample
Running the sample requires the following steps...
1. Collect the mrenclave/mrsigner from the example enclave.
2. Creating an Intel Trust Authority policy that will be evaluated during token creation.
3. Running the SGX Token application via docker on an SGX Host.

### Example Environment Variables
- The following table lists the environment variables used in sgx_token.env

    |Variable			|Description							|
    |:--------------------------|:--------------------------------------------------------------|
    |TRUSTAUTHORITY_API_KEY	|The Intel Trust Authority API key.				|
    |TRUSTAUTHORITY_API_URL	|The Intel Trust Authority API URL.				|
    |TRUSTAUTHORITY_POLICY_ID	|The policy id created using Intel Trust Authority portal.	|
    |TRUSTAUTHORITY_BASE_URL	|The base url of Intel Trust Authority certificate management authority to download certificate to verify token in Azure. (ex. 'https://portal.trustauthority.intel.com')|
    |REQUEST_ID			|An optional parameter to trace the request.			|
    |TOKEN_SIGNING_ALG|An optional parameter to specify token signing algorithm, supported algorithms are RS256, PS384.|
    |POLICY_MUST_MATCH|An optional boolean parameter to enforce policies match during attestation, supported values are true/false.|
    |RETRY_WAIT_TIME		|Wait time between retries. Default value is 2 seconds.		|
    |RETRY_MAX			|Maximum number of retries. Default value is 2 seconds.		|

### Run the example...
```shell
#Creating sgx_token.env file
cat <<EOF | tee sgx_token.env
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
SGX_AESM_ADDR=1
EOF
#Use docker to run the SGX Token example...
sudo docker run -it --rm --device=/dev/sgx_enclave --device=/dev/sgx_provision -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket --env-file sgx_token.env --group-add $(getent group sgx_prv | cut -d: -f3) taas/sgx_token:v1.2.0
```

### Output when example is run...
- When successful, the token and other information will be dispayed...
