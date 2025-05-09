# Azure CVM with Intel TDX and vTPM Attestation Example

<p style="font-size: 0.875em;">· 07 May 2025 ·</p>

The Azure confidential VM with Intel® TDX + vTPM Token example is a C program that uses the Intel® Trust Authority Attestation Client libraries to get an attestation token from Intel® Trust Authority. The program runs inside a trust domain on Azure CVM with Intel TDX.  When run, it collects a quote from the CVM trust domain (TD) and a quote from the vTPM, forming a composite quote, and then sends it to Intel Trust Authority to retrieve a token. If the token request is successful, the contents of the token and other information are printed to the screen. 

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- Azure confidential VM (CVM) with Intel TDX host.
- **tpm2-tools** installed on the Azure CVM.


## Build Instructions

Build the Azure TPM Token docker image in release/debug mode under `trustauthority-client` home folder.

To build the example in release mode, run the following command. 
```shell
make azure_tpm_token_docker
```

To build the example in debug mode, run the following command.
```shell
make DEBUG=1 azure_tpm_token_docker
```

When successfully built, run `docker image ls -a` includes `taas/azure_tpm_token:v1.3.0`.

## Deployment Instructions
The docker image must be present inside the CVM trust domain (TD).  For example, it can be exported/copied from a build machine as follows.

```shell
#Save the azure_tpm_token Docker image into trust_authority.azure_tpm_token.tar.gz
docker save taas/azure_tpm_token:v1.3.0 > trust_authority.azure_tpm_token.tar.gz
#scp trust_authority.azure_tpm_token.tar.gz to the TD VM.
#On the TD VM load/import trust_authority.azure_tpm_token.tar.gz docker image using below command
docker load -i trust_authority.azure_tpm_token.tar.gz
``` 

## Running the Sample

The sample relies on an environment file to provide information such as the API key and Intel Trust Authority base URL. The following table lists the environment variables used in `tpm_token.env`. Most of these are optional for this example, which uses the default values.

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

    

1. Create tpm_token.env by running the following command. Replace values in <> with your values. Note that if you're in the EU, you also have a different API_URL and BASE_URL than shown here.

``` shell
cat <<EOF | tee tpm_token.env
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
TRUSTAUTHORITY_API_URL=https://api.trustauthority.intel.com
TRUSTAUTHORITY_BASE_URL=https://portal.trustauthority.intel.com
EOF
```

2. Run the example in a Docker container
``` shell
sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --privileged -u root -v /sys:/sys --env-file tpm_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_tpm_token:v1.3.0
```

When successful, the token and other information will be displayed.
