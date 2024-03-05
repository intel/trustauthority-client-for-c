# Intel Trust Authority C Client Library 
Intel Trust Authority Client provides a set of C libraries for attesting different TEEs with Intel Trust Authority. Users can link the C libraries within their application and make REST calls to Intel Trust Authority for fetching token containing information about the TEE attested that can be verified.

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Installation

Install the latest version of the library with following commands:

Follow the build instructions of library from [builds.md](./docs/builds.md) 

Installation steps:
1. Copy the libraries built from above steps to application path and export them to LD_LIBRARY_PATH.
2. LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path to libraries generated.>
3. export LD_LIBRARY_PATH

## Usage

If User has interface to get the quote/evidence and want to attest it with Intel Trust Authority:

Create a new Intel Trust Authority client, then use the exposed services to
access different parts of the Intel Trust Authority API.

### Create Connector instance.
```C
trust_authority_connector *connector = NULL;
 /**
 * Creates a new connector client to connect to Intel Trust Authority
 * connector[output] - provides an HTTPClient interface to communicate with Intel Trust Authority via REST APIs.
 * ta_key[input] - API key for Intel Trust Authority
 * ta_api_url[input] - Intel Trust Authority URL 
 * retry_max[input] -  Maximum retires allowed
 * retry_wait_sec[input] - Waiting time in seconds between retries
 */
 status = trust_authority_connector_new(&connector, ta_key, ta_api_url, retry_max, retry_wait_sec);
```

### To get a Intel Trust Authority signed token with Nonce

Create SGX/TDX adapter using
-  [sgx](./src/sgx/README.md)
-  [tdx](./src/tdx/README.md)

Use the adapter created with following piece of code:

```C
token token = {0};
policies policies = {0};
collect_token_args token_args ={0};
evidence_adapter *adapter = NULL;
char *ids[] = {policy_id};
policies.ids = ids;
policies.count = //Number of policies provided
token_args.polices = policies;

/**
 * Gets the token from Intel Trust Authority
 * connector[input] - an HTTPClient interface to communicate with Intel Trust Authority via REST APIs(created using above code)
 *  header[output] - parameter containing all response headers from Intel Trust Authority
 *  token[output] - token struct that will contain the token recieved from Intel Trust Authority
 *  args[input] - request paramater that will part of token request
 *  adapter[input] - sgx/tdx adapter created.
 *  user_data[input] - any additional data user wants to embed into the quote
 *  user_data_len[input] - length of user data
 * */
status = collect_token(connector,
                    &header,
                    &token, 
                    &args,
                    adapter, // recieved from adapter
                    user_data, // any extra data user wants to send.
                    user_data_len);  // length of user data.
                    
if (STATUS_OK != status)  
{ 
    printf("Failed to collect token: 0x%04x\n", status); 
    return status; 
} 
```

### To verify Intel Trust Authority signed token
`char * jwks_data` is optional in this function.  
If user sends `NULL`, jwks will be downloaded from INTEL Trust authority server.  
Else user can send the whole `jwks_data` json in `char *` format.   

```C

/**
 * Verifies the token recieved from Intel Trust Authority
 * token[input] - token to be verified
 * base_url[input] - Intel Trust Authority URL 
 * jwks_data[input] - optional value containing JWKS signing certificate
 * parsed_token[output] - token to be verified
 * retry_max[input] - maximum retires allowed.
 * retry_wait_sec[input] - waiting time in seconds between retries
 * */
status = verify_token(&token,
                    base_url, // Intel Trust Authority API URL 
                    jwks_data, 
                    &parsed_token,
                    retry_max, 
                    retry_wait_sec);

if (STATUS_OK != status)
{  
        printf("Error: Failed to verify token: 0x%04x\n", status);  
        return status;  
}  
```

### To download token signing certificates from Intel Trust Authority

```C
/**
 * Gets token sigining certificate from Intel Trust Authority
 * jwks_url[input] -  Intel Trust Authority URL to get certificates
 * jwks_resp[output] - response from Intel Trust Authority
 * retry_max[input] - maximum retires allowed
 * retry_wait_sec[input] - waiting time in seconds between retries
 * */
result = get_token_signing_certificate(jwks_url, 
                                    &jwks_resp, 
                                    retry_max, 
                                    retry_wait_sec);

if (result != STATUS_OK || jwks_resp == NULL)  
{  
    return STATUS_GET_SIGNING_CERT_ERROR;  
}  
```

### For E2E token collection and signature verification logic refer
SGX: [SGX Sample App](./examples/sgx_token/README.md)
TDX: [TDX Sample App](./examples/tdx_token/README.md)


### Follow below link to run unit tests
[Unit_Test.md](./docs/build_ut_tests.md) 

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
