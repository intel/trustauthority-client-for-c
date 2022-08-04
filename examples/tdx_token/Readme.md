# TDX Token Example
The TDX Token example is a C program that uses the Amber Attestation Client
to collect a token from Amber. The program suppose to run inside a TD.  When run, 
it collects a quote from the TD and sends it to Amber to retrieve a token.

```
┌──────────────────────────────────────────────┐
│    ┌────────────────────────────────────┐    │
│    │          Docker Container          │    │
│    │                                    │    │
│    │    ┌──────────────────────────┐    │    │
│    │    │        TDX Token         │    │    │                ┌────────────────┐
│    │    └──────────────────────────┘    │    │                │                │
│    │                                    │    │                │                │
│    │    ┌──────────────────────────┐    │◄───┼───────────────►│     Amber      │
│    │    │     libAmberTdx.so       │    │    │                │                │
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
│                  TD VM                       │
└──────────────────────────────────────────────┘
```
The diagram above depicts the components used in the TDX Token while running within
a docker container.  The TDX Token example can also be run directly inside a TD vm (provided
the appropriate dependencies like DCAP have been installed). 

## Limitations
- The TDX Token application does not verify the token provided by Amber.
- The TDX Token application only supports a single Amber Policy ID.
- These instructions are specific to using docker to run the TDX Token example.
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
- A *pre-production* TDX host with the TDX kernel and TD installed.
- The TDX host must be able to generate quotes (this may require that the host is "registered" with Amber's instance of TCS).
- A running instance of Amber (see versions above).

## Build Instructions
- Build the TDX Token docker image:  `make tdx_token_docker`
- When successfully built, running `docker image ls -a` includes `amber/tdx_token:v0.2.0`.

## Deployment Instructions
- The docker image must be present inside the TD vm.  For example, it can be exported/copied 
from a build machine as follows...
    - `docker save amber/tdx_token:v0.2.0 > amber.tdx_token.tar.gz`
    - `scp` amber.tdx_token.tar.gz to the TD vm.
    - Inside the TD vm: `docker load -i amber.tdx_token.tar.gz`

## Running the Sample
Running the sample requires the following steps...
1. Collect the measurements from the example application.
2. Creating an Amber policy that will be evaluated during token creation.
3. Optional: Register the TDX host with Amber's instance of TCS to facilitate quote collection.
4. Running the TDX Token application via docker in a TD VM.

### Example Environment Variables
The following table lists the environment variables used in the rest of the instructions...

    |Variable|Description|
    |--------|-----------|
    |AMBER_HOST|The hostname of Amber cluster running in Azure (ex. 'myhost.intel.com').|
    |AMBER_KEY|The Amber API key (aka 'subscription') from by Azure/APIM.|
    |AMBER_POLICY_ID| The policy id that is created below (ex. '7b2b14a2-2d35-4941-8dc4-cd89d6f1141e').|
    |AMBER_INGRESS| The hostname/ip of Amber's ingressgateway to support the client during quote generation.|

### Collecting measurements
This step is needed to create the Amber policy.  
- There is no way to get a TD measurements without launching it. Launch a TD and run TDX token example inside it without specifying policy id. Use the token generated to get the TD measurements.

### Policy Creation
- Export the base url of Amber running in Azure/APIM: `export AMBER_HOST=myambercluster.azure-api.net`
- Export the API Key from Amber's APIM instance in Azure: `export API_KEY=495651f6bd384b08ae9efc7e65fd69bd`
- Create a policy providing the measurements of the TD vm...
    ```shell
    curl --location --request POST "https://${AMBER_HOST}/ps/v1/policies" \
    --header 'Accept: application/json' \
    --header 'TenantId: 99d263a9-5199-41a2-8a5b-7690eaef88af' \
    --header 'Content-Type: application/json' \
    --header "x-api-key: ${API_KEY}" \
    --data-raw '{
        "policy": "default matches_tdx_policy = false \n includes_value(policy_values, quote_value) = true { \n\n policy_value := policy_values[x] \n policy_value == quote_value \n } \n matches_tdx_policy = true { \n\n quote := input.quote \n quote.seamsvn == 0 \n  mrtdValues := [\"2464d69230415996ae19eadc3f6d177f69ad9583f4b71114de31b4bb3f47923a910b69fdb6eef646e0c14fea95daa6e2\"] \n includes_value(mrtdValues, quote.mrtd) \n mrseamValues := [\"b360df71bbf2310e801c76c604de7bc84416917ad8be6c9f25401e6af2c5ecd9c29559374202af9332a58ad114dc29d6\"] \n includes_value(mrseamValues, quote.mrseam) \n mrsignerseamValues:= [ \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"] \n includes_value(mrsignerseamValues, quote.mrsignerseam) \n } \n ",
        "tenant_id": "99d263a9-5199-41a2-8a5b-7690eaef88af",
        "user_id": "7110194b-a703-4657-9d7f-3e02b62f2ed8",
        "version": "v1",
        "policy_name": "TDX_TOKEN_EXAMPLE",
        "policy_type": "Appraisal",
        "service_offer_id": "7ba36c8a-59b5-4f0e-a595-1c2945d5a1ce",
        "service_offer_name": "TDX",
        "subscription_id": "158ccbc6-0ced-4718-ae6a-813684122bf8",
        "subscription_name": "Amber 2"
    }'
    ```
*Note:  The curl command may require the `--noproxy "*"` option depending on your proxy configuration.  It may also require the `-k` option to disable TLS validation.

- Export the AMBER_POLICY_ID (ex. `export AMBER_POLICY_ID=7b2b14a2-2d35-4941-8dc4-cd89d6f1141e`) from JSON results from the policy creation curl command (this will be provided as input to the TDX Token example)...
    ```json
    {"policy_id":"7b2b14a2-2d35-4941-8dc4-cd89d6f1141e","policy":"default matches_tdx_policy = false \n includes_value(policy_values, quote_value) = true { \n\n policy_value := policy_values[x] \n policy_value == quote_value \n } \n matches_tdx_policy = true { \n\n quote := input.quote \n quote.seamsvn == 0 \n  mrtdValues := [\"2464d69230415996ae19eadc3f6d177f69ad9583f4b71114de31b4bb3f47923a910b69fdb6eef646e0c14fea95daa6e2\"] \n includes_value(mrtdValues, quote.mrtd) \n mrseamValues := [\"b360df71bbf2310e801c76c604de7bc84416917ad8be6c9f25401e6af2c5ecd9c29559374202af9332a58ad114dc29d6\"] \n includes_value(mrseamValues, quote.mrseam) \n mrsignerseamValues:= [ \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"] \n includes_value(mrsignerseamValues, quote.mrsignerseam) \n } \n ","tenant_id":"99d263a9-5199-41a2-8a5b-7690eaef88af","version":"v1","policy_name":"TDX_TOKEN_EXAMPLE","policy_type":"Appraisal","service_offer_id":"7ba36c8a-59b5-4f0e-a595-1c2945d5a1ce","service_offer_name":"TDX","subscription_id":"158ccbc6-0ced-4718-ae6a-813684122bf8","subscription_name":"Amber 2","creator_id":"7110194b-a703-4657-9d7f-3e02b62f2ed8","updater_id":"7110194b-a703-4657-9d7f-3e02b62f2ed8","deleted":false,"created_time":"2022-06-03T13:35:06.275280739Z","modified_time":"2022-06-03T13:35:06.275280739Z","policy_hash":"kEPLGlJfRyVnyL9/6e0fnxP7IeIr590nVdsQuLK7mUXJ+s6plMnvfoN3s7MN8tcr","policy_signature":"pBbQeqbvJXVHsNCOamtRYoUow7wTjM1uDTD/hZMyUWmKYF2c2dd9xuw8Z3fH8OZbuF9MfKk3zf6zVzz95PYTfpB+PKQ4b/wG3jVi+leNldKWCFuZjU7omAh3gJOk3hjK5/TsOYtXX//RkSpwtlsLXzdJJV/kG8fWR2nvYi3D56QxvswNQQug5xnvgGSES1p3Ra6RvCopNNRNKxjElVVPRBbK45y7RMycU3Y5ZTBOw9iHI6pX9Mjt5wAWUUpADTsoM6Yj4xO172JfSPUMdsICJNLWIYnefx9+miFx4x/Owex9zGUe1SaNB+Q7LEiMcfmHhez/cjXaoNhvyX63H2atR1wIZvPhkeYoe9mr00ldoiprQ6QCVhGDPY1BcUtZAWhF1x9PijcepLfvzlYQg65hQaTN+xzFFMv+66G23hIV0eX17lYsrYpSjsDmpU1++C+VJAogBpjpWuQ/LGiNMSJKG/RyU84CWbwjcHsgm9CYDplCLTIgmU8WIfBlgc0G5TRt"}
    ```

### TDX Host Registration
The following instructions populate Amber's TCS with platform information to support quote generation.

- On the TDX host, run PCKIDRetrievalTool to generate `pckid_retrieval.csv`.
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
- Use docker to run the TDX Token example...
    ```
    docker run -it --rm --privileged -e AMBER_KEY=$AMBER_KEY -e AMBER_POLICY_ID=$AMBER_POLICY_ID -e AMBER_URL=https://${AMBER_HOST} -e no_proxy=${AMBER_HOST} amber/tdx_token:v0.2.0
    ```
    *Note: Since APIM's domain name may not resolve to an IP address, you may need to provide the hostname and ip via docker's `--add-host` option (ex. `--add-host=myamberhost.azure-api.net:10.11.12.13`).*
- When successful, the token and other information will be dispayed...
    ```
    Connecting to https://10.11.12.13
    Connected to Appraisal Service v0.1.0-e960a7b [2022-06-03T14:59:16+0000]
    Collecting token...
    Amber Token: eyJhbGciOiJSUzM4NCIsImtpZCI6IjBjZWFiOThlMWEyZjZhMDI4NThmZTczNWFkMzFhYWQ4Y2Q0M2Q4YWUiLCJ0eXAiOiJKV1QifQ.eyJtcnNlYW0iOiJiMzYwZGY3MWJiZjIzMTBlODAxYzc2YzYwNGRlN2JjODQ0MTY5MTdhZDhiZTZjOWYyNTQwMWU2YWYyYzVlY2Q5YzI5NTU5Mzc0MjAyYWY5MzMyYTU4YWQxMTRkYzI5ZDYiLCJtcnNpZ25lcnNlYW0iOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJtcnRkIjoiMjQ2NGQ2OTIzMDQxNTk5NmFlMTllYWRjM2Y2ZDE3N2Y2OWFkOTU4M2Y0YjcxMTE0ZGUzMWI0YmIzZjQ3OTIzYTkxMGI2OWZkYjZlZWY2NDZlMGMxNGZlYTk1ZGFhNmUyIiwicnRtcjAiOiI2ZDNmYWVlNzFlYmJlOWFjYzE1YjYwMjExNzMzNmRkMjg3ZjEzNTcwZWRjZjFjYjIwOTJjODc5YTJhMTlkMjZjZTk0MjRiNjRkMjYyOTA1ODc1NjMxOGE1ZTNhODVlMjIiLCJydG1yMSI6IjhmNThlMDVjMjA3ODE3OGE2ZmYxNmY0ZWRjMWUzZTY1ZTllZTM0NjgwMzA2OWNlMWRjZTRlMjUxMzNlZTNiMmMyNTFhNmZiMzM0ZGEyOWZmMWQwNmQ0NzI5ZWUwNGIzMyIsInJ0bXIyIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwicnRtcjMiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZWFtc3ZuIjowLCJwb2xpY3lfaWRzIjpudWxsLCJ0Y2Jfc3RhdHVzIjoiT1VUX09GX0RBVEUiLCJ0ZWUiOiJURFgiLCJ2ZXIiOiIxLjAiLCJleHAiOjE2NTk1OTI4NzksImlhdCI6MTY1OTU5MjU0OSwiaXNzIjoiQVMgQXR0ZXN0YXRpb24gVG9rZW4gSXNzdWVyIn0.KVqBjhLKf1AC5iP9Or0iyzA4nZx2XoZHeDBXNoo1SNzOmK7n-o8Q8cE2Y3ary54YdPpMxQ0ZyRgEAWuXm3zX_XBxWNkzIzWutZcz2fymGuYxmu7s-YFOMk5QbPe5UCE1do6qpLU2A7ktwlsTH1hxGtGTkzacW1hm-uZjEAWIaexLT3tEFtBZtwfUuNffmrYIYzWS_8iowBYG1200thu7UblgiuMdnq9v-xtrrq-fS2-HG6TIFXft2o93W324ltAT8WGqF8RI-E023YR67QyPk5qFqLCxvOZvjsCrRSNRZsli0yaHfsnpYg3Q9DVenxn3yC_d9itEvb6_VuLSFGv_Dqk351RZLDyoQbO6C6wQ5iaV-wg1Tl8DRTqOFsMZCif1iHQC1atOFeIlMLPiO49xSlE48y6GcRuBFVnQCzkGj97j7PsGnYL-ejq4nkj_U1TuvXLlgibDO37ks4UZ9aTtbEDFJ6mEaay48tW1TcwL7vdVmLGRp2ftcZ9G0DUKLQn_
    ```
- The token claims from jwt.io are shown below...
    ```json
    {
        "mrseam": "b360df71bbf2310e801c76c604de7bc84416917ad8be6c9f25401e6af2c5ecd9c29559374202af9332a58ad114dc29d6",
        "mrsignerseam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "mrtd": "2464d69230415996ae19eadc3f6d177f69ad9583f4b71114de31b4bb3f47923a910b69fdb6eef646e0c14fea95daa6e2",
        "rtmr0": "6d3faee71ebbe9acc15b602117336dd287f13570edcf1cb2092c879a2a19d26ce9424b64d2629058756318a5e3a85e22",
        "rtmr1": "8f58e05c2078178a6ff16f4edc1e3e65e9ee346803069ce1dce4e25133ee3b2c251a6fb334da29ff1d06d4729ee04b33",
        "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "saemsvn": 0,
        "policy_ids": [
            "7b2b14a2-2d35-4941-8dc4-cd89d6f1141e"
        ],
        "tcb_status": "OUT_OF_DATE",
        "tee": "TDX",
        "ver": "1.0",
        "exp": 1653413453,
        "iat": 1653413123,
        "iss": "AS Attestation Token Issuer"
    }
    ```