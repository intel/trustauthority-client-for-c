# Intel® SGX Attestation Example

<p style="font-size: 0.875em;">· 07 May 2025 ·</p>

The Intel® Software Guard Extensions (Intel® SGX) attestation example is a C program that uses the Intel® Trust Authority Attestation Client libraries to request an attestation token from Intel Trust Authority. The program contains an example Intel SGX enclave. When run, it collects a quote from the enclave and sends it to Intel Trust Authority to retrieve a token.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │      Intel SGX Token     │      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│ INTEL TRUST    |
│    │    │     enclave.signed.so    │      │    │                │ AUTHORITY      |
│    │    └──────────────────────────┘      │    │                │ SERVER         |
│    │                                      │    │                └────────────────┘   
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    | libtrustauthority_sgx.so |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      │    │
│    │    │    libtrustauthority_    |      |    |
|    |    |    connector.so          │      │    │
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │    libtrustauthority_      |    |    |
|    |    |    evidence_builder.so     │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │    libtrustauthority_      |    |    |
|    |    |    token_verifier.so       │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  Intel SGX VM                  │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the Intel SGX Token example while running within a docker container. The Intel SGX Token example can also be run directly on an Intel SGX Host (provided the appropriate dependencies like Intel® SGX DCAP have been installed).

## Prerequisites

- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *production* SGX host with the SGX driver and Docker installed.
- The SGX host must be able to generate quotes.
- A running instance of Intel Trust Authority.

## Build and Run Instructions

1. Build  SGX Token docker image in release/debug mode:

```shell
  - To Build in release mode:  
	make sgx_token_docker
  - To Build in debug mode:  
	make DEBUG=1 sgx_token_docker
```
When successfully built, running `docker image ls -a` includes `taas/sgx_token:v1.3.0`.


2. The docker image must be present on the SGX host.  For example, it can be exported/copied from a build machine as follows...
```shell
#Save the sgx_token Docker image into trust_authority.sgx_token.tar.gz
docker save taas/sgx_token:v1.3.0 > trust_authority.sgx_token.tar.gz
#scp trust_authority.sgx_token.tar.gz to the SGX host.
#On the SGX host load/import trust_authority.sgx_token.tar.gz docker image using below command
docker load -i trust_authority.sgx_token.tar.gz
```

The example app relies on an environment file to provide the API key and other information. In the next step, you'll create the environment file. The following table lists the environment variables used in sgx_token.env, however, all but the first four are optional for this example.

    |Variable			|Description							|
    |:--------------------------|:--------------------------------------------------------------|
    |TRUSTAUTHORITY_API_KEY	|The Intel Trust Authority API key.				|
    |TRUSTAUTHORITY_API_URL	|The Intel Trust Authority API URL.				|
    |TRUSTAUTHORITY_POLICY_ID	|The policy id created using Intel Trust Authority portal.	|
    |TRUSTAUTHORITY_BASE_URL	|The base url of Intel Trust Authority certificate management authority to download certificate to verify token in Azure. (ex. 'https://portal.trustauthority.intel.com')|
    |REQUEST_ID			|An optional parameter to trace the request.		|
    |TOKEN_SIGNING_ALG|An optional parameter to specify token signing algorithm, supported algorithms are RS256, PS384. The default is PS384.|
    |POLICY_MUST_MATCH|An optional boolean parameter to enforce policies match during attestation, supported values are true/false. The default is False.|
    |RETRY_WAIT_TIME		|Wait time between retries. Default value is 2 seconds.		|
    |RETRY_MAX			|Maximum number of retries. Default value is 2 seconds.		|

3. Create the `sgx_token.env` file

```shell
cat <<EOF | tee sgx_token.env
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
TRUSTAUTHORITY_API_URL=https://api.trustauthority.intel.com
TRUSTAUTHORITY_BASE_URL=https://portal.trustauthority.intel.com
SGX_AESM_ADDR=1
EOF
```

4. Use Docker to run the Intel SGX attestation token example.

```shell
sudo docker run -it --rm --device=/dev/sgx_enclave --device=/dev/sgx_provision -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket --env-file sgx_token.env --group-add $(getent group sgx_prv | cut -d: -f3) taas/sgx_token:v1.3.0
```

If the token request is successful, the contents of the attestation token and other information are printed to the screen.
