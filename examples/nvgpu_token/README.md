# NVGPU Token Example
The NVGPU Token example is a C program that uses the Intel Trust Authority Attestation Client libraries
to fetch token from Intel Trust Authority. The program contains an example NVGPU H100 host. When run, 
it collects GPU evidence from the NVGPU H100 and sends it to Intel Trust Authority to retrieve a token.

```
On TDX box
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │        NVGPU Token       │      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
│    │    ┌──────────────────────────┐      │◄───┼───────────────►│ INTEL TRUST    |
│    │    │    libnvidia-ml.so       │      │    │                │ AUTHORITY      |
│    │    └──────────────────────────┘      │    │                │ SERVER         |
│    │                                      │    │                └────────────────┘   
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |libtrustauthotiy_nvgpu.so |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |libtrustauthotiy_tdx.so   |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |libtrust.._evi_builder.so |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      │    │
│    │    │      libtrustauthotiy_   |      |    |
|    |    |      connector.so        │      │    │
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │  libtrustauthotiy_         |    |    |
|    |    |  token_verifier.so         │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  NVIDIA GPU Host               │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the NVGPU Token while running within
a docker container. The NVGPU Token example can also be run directly on a NVIDIA H100 host.

## Prerequisites
- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *production* NVGPU host with the NVIDIA driver and Docker installed.
- The NVGPU host must be able to generate GPU evidence with CC_mode enabled.
- NVIDIA container toolkit Installed (see [NVIDIA Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html))
- A running instance of Intel Trust Authority.

## Build Instructions
- Build  NVGPU Token docker image in release/debug mode under project root directory:
```shell
  - To Build in release mode:  
  docker build -f examples/nvgpu_token/Dockerfile -t taas/nvgpu_token:v1.2.0 .
  - To Build in debug mode:  
	docker build --build-arg ENABLE_DEBUG=Debug -f examples/nvgpu_token/Dockerfile -t taas/nvgpu_token:v1.2.0 .
```
- When successfully built, running `docker image ls -a` includes `taas/nvgpu_token:v1.2.0`.

## Deployment Instructions

- The docker image must be present on the NVGPU host.  For example, it can be exported/copied from a build machine as follows...
```shell
#Save the nvgpu_token Docker image into trust_authority.nvgpu_token.tar.gz
docker save taas/nvgpu_token:v1.2.0 > trust_authority.nvgpu_token.tar.gz
#scp trust_authority.nvgpu_token.tar.gz to the nvgpu host.
#On the nvgpu host load/import trust_authority.nvgpu_token.tar.gz docker image using below command
docker load -i trust_authority.nvgpu_token.tar.gz
```

## Running the Sample
Running the sample requires the following steps...
1. Collect the NVGPU evidence and certificate chain from the example NVIDIA H100 host.
2. Creating an Intel Trust Authority policy that will be evaluated during token creation.
3. Running the NVGPU Token application via docker on an NVGPU Host.

### Example Environment Variables
- The following table lists the environment variables used in nvgpu_token.env

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
#Creating nvgpu_token.env file
cat <<EOF | tee nvgpu_token.env
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
TRUSTAUTHORITY_API_URL="https://api.trustauthority.intel.com"
TRUSTAUTHORITY_BASE_URL="https://portal.trustauthority.intel.com"
EOF
#Use docker to run the nvgpu Token example...
sudo docker run --privileged -u root -v /sys/kernel/config:/sys/kernel/config --rm --runtime=nvidia --gpus all --env-file nvgpu_token.env taas/nvgpu_token:v1.2.0
```

### Output when example is run...
- When successful, the token and other information will be displayed...
