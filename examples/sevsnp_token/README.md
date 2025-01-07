# Sevsnp Token Example
The Sevsnp Token example is a C program that uses the Intel Trust Authority Attestation Client libraries
to fetch token from Intel Trust Authority. The program suppose to run inside a sevsnp VM.  When run, 
it collects a report from the Sevsnp VM and sends it to Intel Trust Authority to retrieve a token. 

## Build Instructions
- Build the Sevsnp Token docker image in release/debug mode:
```shell
  - To Build in release mode:  
	make sevsnp_token_docker
  - To Build in debug mode:  
	make DEBUG=1 sevsnp_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/sevsnp_token:v1.2.0`.

**_NOTE:_** If you are building for Azure, use below commands:
```shell
  - To Build in release mode:
	make azure_sevsnp_token_docker
  - To Build in debug mode:
	make DEBUG=1 azure_sevsnp_token_docker
```
- When successfully built, running `docker image ls -a` includes `taas/azure_sevsnp_token:v1.2.0`.

## Deployment Instructions
- The docker image must be present inside the sevsnp vm.  For example, it can be exported/copied 
from a build machine as follows...
```shell
#Save the sevsnp_token Docker image into trust_authority.sevsnp_token.tar.gz
docker save taas/sevsnp_token:v0.1.0 > trust_authority.sevsnp_token.tar.gz
#scp trust_authority.sevsnp_token.tar.gz to the sevsnp vm.
#On the sevsnp vm load/import trust_authority.sevsnp_token.tar.gz docker image using below command
docker load -i trust_authority.sevsnp_token.tar.gz
``` 

## Running the Sample
Running the sample requires the following steps...
1. Collect the measurements from the example application.
2. Creating an Intel Trust Authority policy that will be evaluated during token creation (Please use the Composite Attestation policy format).
3. Running the Sevsnp Token application via docker in a sevsnp VM.

### Example Environment Variables
- The following table lists the environment variables used in tdx_token.env
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
    

### Run the example...
- Use docker to run the Sevsnp Token example...
    ```
    cat <<EOF | tee sevsnp_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL="https://api.pilot.trustauthority.intel.com"
    TRUSTAUTHORITY_BASE_URL="https://portal.pilot.trustauthority.intel.com"
    EOF
    sudo docker run -it --rm --privileged --network host -v /sys/kernel/config:/sys/kernel/config  --env-file sevsnp_token.env taas/sevsnp_token:v1.2.0
    ```

- Use docker to run the Azure Sevsnp Token example...
    ```
    cat <<EOF | tee sevsnp_token.env
    TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
    TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
    TRUSTAUTHORITY_API_URL="https://api.pilot.trustauthority.intel.com"
    TRUSTAUTHORITY_BASE_URL="https://portal.pilot.trustauthority.intel.com"
    EOF

    sudo docker run -it --rm --device=/dev/tpm0 --device=/dev/tpmrm0 --env-file sevsnp_token.env --group-add $(getent group tss | cut -d: -f3) taas/azure_sevsnp_token:v1.2.0
    ```

### Output when Sevsnp example is run...
- When successful, the token and other information will be displayed...