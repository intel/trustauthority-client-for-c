# Azure TDX + vTPM Token Example
The Azure TDX + vTPM Token example is a C program that uses the Intel Trust Authority Attestation Client libraries
to fetch token from Intel Trust Authority. The program suppose to run inside a TD with vTPM support.  When run, 
it collects a quote from the TD and a quote from vTPM, forming a composite evidence and sends it to Intel Trust Authority to retrieve a token.

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- Azure TDX host with vTPM support.
- tpm2-tools.
- A running instance of Intel Trust Authority (see versions above).

## Build Instructions
- Build the Azure TPM Token docker image in release/debug mode under trustauthority-client home folder:
```shell
  - To Build in release mode:  
	make azure_tpm_token_docker
  - To Build in debug mode:  
	make DEBUG=1 azure_tpm_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/azure_tpm_token:v1.2.0`.

## Deployment Instructions
- The docker image must be present inside the TD vm.  For example, it can be exported/copied 
from a build machine as follows...
```shell
#Save the azure_tpm_token Docker image into trust_authority.azure_tpm_token.tar.gz
docker save taas/azure_tpm_token:v0.1.0 > trust_authority.azure_tpm_token.tar.gz
#scp trust_authority.azure_tpm_token.tar.gz to the TD VM.
#On the TD VM load/import trust_authority.azure_tpm_token.tar.gz docker image using below command
docker load -i trust_authority.azure_tpm_token.tar.gz
``` 

## Running the Sample
Running the sample requires the following steps...
1. Collect the measurements from the example application.
2. Creating an Intel Trust Authority policy that will be evaluated during token creation.
3. Running the Azure TPM Token application via docker in a TD VM.

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
    |TPM_WITH_IMA_LOGS|When "true", includes IMA logs into TPM evidence.|
    |TPM_WITH_UEFI_LOGS|When "true", includes UEFI event logs into TPM evidence.|
    

### Run the example...
- Use docker to run the Azure TPM Token example...
    ```
    cat <<EOF | tee tpm_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
    TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
    EOF

    sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --env-file tpm_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_tpm_token:v1.2.0
    ```

### Output when Azure TPM example is run...
- When successful, the token and other information will be displayed...
