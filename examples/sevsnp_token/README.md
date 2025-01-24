# AMD SEV-SNP Token Example

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

The AMD SEV-SNP\* token example is a C program that uses the Intel® Trust Authority Attestation Client libraries to request an attestation token from Intel Trust Authority. The example runs inside a confidential VM (CVM) with SEV-SNP. When run, the example collects evidence for a quote from the CVM, and then sends it to Intel Trust Authority for attestation.  

> [!NOTE]
> AMD SEV-SNP attestation is currently in limited preview status in the Intel Trust Authority pilot environment only. For preview access, please contact your Intel representative.

## Build Instructions

You can build the SEV-SNP token example Docker image in release or debug mode using the following commands.

### Build for on-premises or Google Cloud Platform

To build the example in release mode:
```shell
make sevsnp_token_docker
```
To build the example in debug mode:
```shell
make DEBUG=1 sevsnp_token_docker
```
When successfully built, running `docker image ls -a` includes `taas/sevsnp_token:v1.3.0`.

### Build for Azure 

To build the example in release mode:
```shell
make azure_sevsnp_token_docker
```
To build the example in debug mode:
```shell
make DEBUG=1 azure_sevsnp_token_docker
```
When successfully built, running `docker image ls -a` includes `taas/azure_sevsnp_token:v1.3.0`.

## Deployment Instructions

The Docker image must be present inside the SEV-SNP CVM.  For example, it can be copied from a build machine as follows.

```shell
#Save the sevsnp_token Docker image into trust_authority.sevsnp_token.tar.gz
docker save taas/sevsnp_token:v1.3.0 > trust_authority.sevsnp_token.tar.gz
#scp trust_authority.sevsnp_token.tar.gz to the sevsnp vm.
#On the sevsnp vm load/import trust_authority.sevsnp_token.tar.gz docker image using below command
docker load -i trust_authority.sevsnp_token.tar.gz
``` 


The example relies on an environment file for information such as the API key and Intel Trust Authority base URL. The following table lists the environment variables used in `sevsnp_token.env`.

    |Variable|Description|
    |:--------|:-----------|
    |TRUSTAUTHORITY_API_KEY|The Intel Trust Authority API key.|
    |TRUSTAUTHORITY_POLICY_ID|The policy id created using Intel Trust Authority portal.|
    |TRUSTAUTHORITY_API_URL|The Intel Trust Authority API URL.| 
    |TRUSTAUTHORITY_BASE_URL|The base url of Intel Trust Authority certificate management authority to download certificate to verify token in Azure. (ex. "https://portal.pilot.trustauthority.intel.com")|
    |REQUEST_ID|An optional parameter to trace the request.|
    |TOKEN_SIGNING_ALG|An optional parameter to specify token signing algorithm, supported algorithms are RS256, PS384.|
    |POLICY_MUST_MATCH|An optional boolean parameter to enforce policies match during attestation, supported values are true/false.|
    |RETRY_WAIT_TIME|Wait time between retries. Default value is 2 seconds.|
    |RETRY_MAX|Maximum number of retries. Default value is 2 seconds.|
    
1. Create the sevsnp_token.env file


  ```shell
  cat <<EOF | tee sevsnp_token.env
  TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
  TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
  TRUSTAUTHORITY_API_URL="https://api.pilot.trustauthority.intel.com"
  TRUSTAUTHORITY_BASE_URL="https://portal.pilot.trustauthority.intel.com"
  EOF
  ```

2. Run the example in the Docker container you built previously.

  ```shell
  sudo docker run -it --rm --privileged --network host -v /sys/kernel/config:/sys/kernel/config  --env-file sevsnp_token.env taas/sevsnp_token:v1.3.0
  ```

  ```shell
  sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --env-file sevsnp_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_sevsnp_token:v1.3.0
  ```

When the example is successfully run, the attestation token and other information will be displayed.


<br><br>

---
**\*** Other names and brands may be claimed as the property of others.