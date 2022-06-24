# SGX Token Example
The SGX Token example is a C program that uses the Amber Attestation Client
to collect a token from Amber. The program contains an example SGX enclave.  When run, 
it collects a quote from the enclave and sends it to Amber to retrieve a token.

```
┌──────────────────────────────────────────────┐
│    ┌────────────────────────────────────┐    │
│    │          Docker Container          │    │
│    │                                    │    │
│    │    ┌──────────────────────────┐    │    │
│    │    │        SGX Token         │    │    │                ┌────────────────┐
│    │    └──────────────────────────┘    │    │                │                │
│    │                                    │    │                │                │
│    │    ┌──────────────────────────┐    │◄───┼───────────────►│     Amber      │
│    │    │     enclave.signed.so    │    │    │                │                │
│    │    └──────────────────────────┘    │    │                │                │
│    │                                    │    │                └────────────────┘
│    │    ┌──────────────────────────┐    │    │
│    │    │      libAmberApi.so      │    │    │
│    │    └──────────────────────────┘    │    │
│    │                                    │    │
│    │    ┌──────────────────────────┐    │    │
│    │    │ libAmberTokenProvider.so │    │    │
│    │    └──────────────────────────┘    │    │
│    │                                    │    │
│    │    ┌──────────────────────────┐    │    │
│    │    │ libAmberTokenVerifier.so │    │    │
│    │    └──────────────────────────┘    │    │
│    │                                    │    │
│    └────────────────────────────────────┘    │
│                                              │
│                  SGX Host                    │
└──────────────────────────────────────────────┘
```
The diagram above depicts the components used in the SGX Token while running within
a docker container.  The SGX Token example can also be run directly on an SGX host (provided
the appropriate dependencies like DCAP have been installed). 

## Limitations
- The SGX Token application does not verify the token provided by Amber.
- The SGX Token application only supports a single Amber Policy ID.
- These instructions are specific to using docker to run the SGX Token example.
- These instructions use Amber's version of TCS during quote generation.  This
service is not currently exposed via APIM -- the sample communicates directly
to the Amber cluster ingressgateway.
- These instructions are known to work against the following versions of Amber...
    ```
    helm                           v0.1.0-f65840c
    appraisal-service              v0.1.0-e960a7b
    policy-service                 v0.1.0-104aad8
    quote-verification-service     v0.1.0-1284074
    tee-caching-service            v0.1.0-aee3c50
    policy-provisioner             v0.1.0-4f1861c
    ```

## Prerequisites
- Ability to build the Amber Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *production* SGX host with the SGX driver and Docker installed.
- The SGX host must be able to generate quotes (this may require that the host is "registered" with Amber's instance of TCS).
- A running instance of Amber (see versions above).

## Build Instructions
- Build the SGX Token docker image:  `make sgx_token_docker`
- When successfully built, running `docker image ls -a` includes `amber/sgx_token:v0.1.0`.

## Deployment Instructions
- The docker image must be present on the SGX host.  For example, it can be exported/copied 
from a build machine as follows...
    - `docker save amber/sgx_token:v0.1.0 > amber.sgx_token.tar.gz`
    - `scp` amber.sgx_token.tar.gz to the SGX host.
    - On the SGX host: `docker load -i amber.sgx_token.tar.gz`

## Running the Sample
Running the sample requires the following steps...
1. Collect the mrenclave/mrsigner from the example enclave.
2. Creating an Amber policy that will be evaluated during token creation.
3. Optional: Register the SGX host with Amber's instance of TCS to facilitate quote collection (needed for on-prem SGX hosts).
4. Running the SGX Token application via docker on an SGX Host.

### Example Environment Variables
The following table lists the environment variables used in the rest of the instructions...

    |Variable|Description|
    |--------|-----------|
    |AMBER_HOST|The hostname of Amber cluster running in Azure (ex. 'myhost.intel.com').|
    |AMBER_KEY|The Amber API key (aka 'subscription') from by Azure/APIM.|
    |AMBER_POLICY_ID| The policy id that is created below (ex. 'f81ae04d-fcdc-4284-87ca-f2f486b0654f').|
    |AMBER_INGRESS| The hostname/ip of Amber's ingressgateway to support the client during quote generation.|

### Collecting mrenclave/mrsigner
This step is needed to create the Amber policy.  *Note:  The sample's enclave measurements are subject to change.*
- The build creates a "dump" file using 'sgx_sign dump' (in `{{sgx sdk}}/bin/x64`).  It build and copied to bin/{distribution}/enclave.signed.info during the build.
- Open the file with an editor to extract the `metadata->enclave_css.body.enclave_hash.m` and `mrsigner->value` values (shown below)...
    ```
        metadata->enclave_css.body.enclave_hash.m:
        0xf9 0xf8 0x64 0xa3 0xe8 0x18 0xa9 0x7b 0xf4 0x79 0xbc 0x5a 0x52 0xcd 0xb7 0xca 
        0x78 0x50 0x0f 0x6e 0x1b 0x8a 0xee 0x0f 0x99 0x1a 0x84 0xae 0xe2 0x51 0x48 0xd0 
        
        mrsigner->value:
        0x83 0xd7 0x19 0xe7 0x7d 0xea 0xca 0x14 0x70 0xf6 0xba 0xf6 0x2a 0x4d 0x77 0x43 
        0x03 0xc8 0x99 0xdb 0x69 0x02 0x0f 0x9c 0x70 0xee 0x1d 0xfc 0x08 0xc7 0xce 0x9e 
    ```
- The above values become...
    ```
    mrenclave: f9f864a3e818a97bf479bc5a52cdb7ca78500f6e1b8aee0f991a84aee25148d0
    mrsigner:  83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
    ```

### Policy Creation
- Export the base url of Amber running in Azure/APIM: `export AMBER_HOST=myambercluster.azure-api.net`
- Export the API Key from Amber's APIM instance in Azure: `export API_KEY=495651f6bd384b08ae9efc7e65fd69bd`
- Create a policy providing the mrsigner/mrenclave of the example's SGX enclave...
    ```shell
    curl --location --request POST "https://${AMBER_HOST}/ps/v1/policies" \
    --header 'Accept: application/json' \
    --header 'TenantId: 99d263a9-5199-41a2-8a5b-7690eaef88af' \
    --header 'Content-Type: application/json' \
    --header "x-api-key: ${API_KEY}" \
    --data-raw '{
        "policy": "default matches_sgx_policy = false \n includes_value(policy_values, quote_value) = true { \n\n policy_value := policy_values[x] \n policy_value == quote_value \n } \n matches_sgx_policy = true { \n\n quote := input.quote \n quote.isvsvn == 0 \n  isvprodidValues := [0, 2, 3] \n includes_value(isvprodidValues, quote.isvprodid) \n mrenclaveValues := [\"f9f864a3e818a97bf479bc5a52cdb7ca78500f6e1b8aee0f991a84aee25148d0\"] \n includes_value(mrenclaveValues, quote.mrenclave) \n mrsignerValues:= [ \"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e\"] \n includes_value(mrsignerValues, quote.mrsigner) \n } \n ",
        "tenant_id": "99d263a9-5199-41a2-8a5b-7690eaef88af",
        "user_id": "7110194b-a703-4657-9d7f-3e02b62f2ed8",
        "version": "v1",
        "policy_name": "SGX_TOKEN_EXAMPLE",
        "policy_type": "Appraisal",
        "service_offer_id": "7ba36c8a-59b5-4f0e-a595-1c2945d5a1ce",
        "service_offer_name": "SGX",
        "subscription_id": "158ccbc6-0ced-4718-ae6a-813684122bf8",
        "subscription_name": "Amber 2"
    }'
    ```
*Note:  The curl command may require the `--noproxy "*"` option depending on your proxy configuration.  It may also require the `-k` option to disable TLS validation.

- Export the AMBER_POLICY_ID (ex. `export AMBER_POLICY_ID=f81ae04d-fcdc-4284-87ca-f2f486b0654f`) from JSON results from the policy creation curl command (this will be provided as input to the SGX Token example)...
    ```json
    {"policy_id":"f81ae04d-fcdc-4284-87ca-f2f486b0654f","policy":"default matches_sgx_policy = false \n includes_value(policy_values, quote_value) = true { \n\n policy_value := policy_values[x] \n policy_value == quote_value \n } \n matches_sgx_policy = true { \n\n quote := input.quote \n quote.isvsvn == 0 \n  isvprodidValues := [0, 2, 3] \n includes_value(isvprodidValues, quote.isvprodid) \n mrenclaveValues := [\"f9f864a3e818a97bf479bc5a52cdb7ca78500f6e1b8aee0f991a84aee25148d0\"] \n includes_value(mrenclaveValues, quote.mrenclave) \n mrsignerValues:= [ \"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e\"] \n includes_value(mrsignerValues, quote.mrsigner) \n } \n ","tenant_id":"99d263a9-5199-41a2-8a5b-7690eaef88af","version":"v1","policy_name":"SGX_TOKEN_EXAMPLE","policy_type":"Appraisal","service_offer_id":"7ba36c8a-59b5-4f0e-a595-1c2945d5a1ce","service_offer_name":"SGX","subscription_id":"158ccbc6-0ced-4718-ae6a-813684122bf8","subscription_name":"Amber 2","creator_id":"7110194b-a703-4657-9d7f-3e02b62f2ed8","updater_id":"7110194b-a703-4657-9d7f-3e02b62f2ed8","deleted":false,"created_time":"2022-06-03T13:35:06.275280739Z","modified_time":"2022-06-03T13:35:06.275280739Z","policy_hash":"kEPLGlJfRyVnyL9/6e0fnxP7IeIr590nVdsQuLK7mUXJ+s6plMnvfoN3s7MN8tcr","policy_signature":"pBbQeqbvJXVHsNCOamtRYoUow7wTjM1uDTD/hZMyUWmKYF2c2dd9xuw8Z3fH8OZbuF9MfKk3zf6zVzz95PYTfpB+PKQ4b/wG3jVi+leNldKWCFuZjU7omAh3gJOk3hjK5/TsOYtXX//RkSpwtlsLXzdJJV/kG8fWR2nvYi3D56QxvswNQQug5xnvgGSES1p3Ra6RvCopNNRNKxjElVVPRBbK45y7RMycU3Y5ZTBOw9iHI6pX9Mjt5wAWUUpADTsoM6Yj4xO172JfSPUMdsICJNLWIYnefx9+miFx4x/Owex9zGUe1SaNB+Q7LEiMcfmHhez/cjXaoNhvyX63H2atR1wIZvPhkeYoe9mr00ldoiprQ6QCVhGDPY1BcUtZAWhF1x9PijcepLfvzlYQg65hQaTN+xzFFMv+66G23hIV0eX17lYsrYpSjsDmpU1++C+VJAogBpjpWuQ/LGiNMSJKG/RyU84CWbwjcHsgm9CYDplCLTIgmU8WIfBlgc0G5TRt"}
    ```

### SGX Host Registration
If the SGX host is "on-prem", Amber's TCS can be used during quote generation.  This is not needed for Azure confidential VMs.  The following instructions populate Amber's TCS with platform information to support quote generation.

- On the SGX host, run PCKIDRetrievalTool to generate `pckid_retrieval.csv`.
- Create `register.json` that can be posted to TCS in Amber...
    ```			
    IFS=',' read -r -a retrieval <<< $(cat pckid_retrieval.csv)
			
    jq --null-input \
        --arg enc_ppid ${retrieval[0]^^} \
        --arg  pce_id ${retrieval[1]^^} \
        --arg cpu_svn ${retrieval[2]^^} \
        --arg pce_svn ${retrieval[3]^^} \
        --arg qe_id ${retrieval[4]^^} \
        '{"enc_ppid": $enc_ppid, "cpu_svn": $cpu_svn, "pce_id": $pce_id, "pce_svn": $pce_svn, "qe_id": $qe_id}' > register.json
    ```
- Post `register.json` to Amber's instance of TCS...
    ```
    curl --location --request POST "https://${AMBER_INGRESS}/tcs/v1/sgx/platforms" --header 'Accept: application/json' --header 'Content-Type: application/json' -d @register.json -k --noproxy "*"
    ```

### Run the example...
- Use docker to run the SGX Token example...
    ```
    docker run -it --rm --privileged -e AMBER_KEY=$AMBER_KEY -e AMBER_POLICY_ID=$AMBER_POLICY_ID -e AMBER_URL=https://${AMBER_HOST} -e PCCS_URL=https://${AMBER_INGRESS}/tcs/v1/sgx/ -e no_proxy=${AMBER_HOST} amber/sgx_token:v0.1.0
    ```
    *Note: Since APIM's domain name may not resolve to an IP address, you may need to provide the hostname and ip via docker's `--add-host` option (ex. `--add-host=myamberhost.azure-api.net:10.11.12.13`).*
- When successful, the token and other information will be dispayed...
    ```
    Connecting to https://10.11.12.13
    Connected to Appraisal Service v0.1.0-e960a7b [2022-06-03T14:59:16+0000]
    Loading enclave...
    Enclave path : enclave.signed.so
    SGX_DEBUG_FLAG : 0
    Enclave loaded.
    Enclave initialized with eid : 2

    Step1: Call create_app_enclave_report:
    Step1: Call sgx_qe_get_target_info:succeed!
    Step2: Call enclave_create_report:succeed!succeed!
    Step2: Call sgx_qe_get_quote_size:succeed!
    Step3: Call sgx_qe_get_quote:succeed!
    cert_key_type = 0x5
    Destroying enclave with eid: 2
    Amber Token: eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJtcmVuY2xhdmUiOiJmOWY4NjRhM2U4MThhOTdiZjQ3OWJjNWE1MmNkYjdjYTc4NTAwZjZlMWI4YWVlMGY5OTFhODRhZWUyNTE0OGQwIiwibXJzaWduZXIiOiI4M2Q3MTllNzdkZWFjYTE0NzBmNmJhZjYyYTRkNzc0MzAzYzg5OWRiNjkwMjBmOWM3MGVlMWRmYzA4YzdjZTllIiwiaXN2cHJvZGlkIjowLCJpc3Zzdm4iOjAsInBvbGljeV9pZHMiOm51bGwsInRjYl9zdGF0dXMiOiJPSyIsInRlZSI6IlNHWCIsInZlciI6IjEuMCIsImV4cCI6MTY1NDI3MTE4MSwiaWF0IjoxNjU0MjcwODUxLCJpc3MiOiJBUyBBdHRlc3RhdGlvbiBUb2tlbiBJc3N1ZXIifQ.EvHBsgCh8je6_Ev_XlljJHfNPIqjcvNQpOXzE2knYZVIVNEvoanbyyB31QR3dLO3O0A9ofPuFXFK2IKprlNP9oHQtjDCMVroYwcE2_ViKjCJJZFcnfqChVI4_BTtX185V2VwMQXqSmYONecrpDlXFQxuX3BWnjXggP0PBu3Y4zX45CY5-yGG6fV-jp7woQHhHgnO-YYBMXikk2-gKlVGXd-vZ5pBICtsbphj-LiMzclAdATiCifnVLgVXlKFJvDk_kSYMxz_fRFbCMffS9fYtayXJbtL2NOQO38aPvClMWHmo3DnAwQdR1ngO4QmxhLgJ3yl7EOJDsFkNrr4jSAwnHITZmpv_9hDLrzs6-EPD4bo8r_OGiwwUDylHDMTjvJLjCHcGEilwohDdDUfEeNgDe-It8M_X95ZrwjxPAK3HwOuePKX9AbYtzp3BHghIm2ULJnV7iRBOSwA87CRnPqzJrxhP7xre2jYWDOErVFQk1Q2ELqST7IqgIOWHr7yq_pd
    ```
- The token claims from jwt.io are shown below...
    ```json
    {
        "mrenclave": "f9f864a3e818a97bf479bc5a52cdb7ca78500f6e1b8aee0f991a84aee25148d0",
        "mrsigner": "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e",
        "policy_ids": [
            "c342f680-f559-4b42-8eb8-f0d2a91c8962"
        ],
        "tcb_status": "OK",
        "tee": "SGX",
        "ver": "1.0",
        "exp": 1653413453,
        "iat": 1653413123,
        "iss": "AS Attestation Token Issuer"
    }
    ```