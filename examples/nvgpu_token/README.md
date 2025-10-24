# NVIDIA H100 Attestation Token Example

<p style="font-size: 0.875em;">· 07 Oct 2025 ·</p>

The NVIDIA H100 GPU attestation example ("NVGPU") is a C program that uses the Intel® Trust Authority Attestation Client libraries to to attest the GPU and the Intel® Trust Domain Extensions (Intel® TDX) host. When run, NVGPU collects GPU evidence from the NVGPU H100, and then sends a quote to Intel Trust Authority to retrieve an attestation token. If attestation is successful, NVGPU prints the contents of the token and other information to the screen.

```
Intel TDX host
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
│    │    |libtrustauthority_nvgpu.so|      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    | libtrustauthority_tdx.so |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      |    |                                                  
│    │    |    libtrustauthority_    |      |    |
|    |    |    evidence_builder.so   |      |    |
│    │    └──────────────────────────┘      │    │
│    │                                      │    │              
│    │    ┌──────────────────────────┐      │    │
│    │    │    libtrustauthority_    |      |    |
|    |    |    connector.so          │      │    │
│    │    └──────────────────────────┘      │    │
│    │                                      │    │
│    │    ┌────────────────────────────┐    │    │
│    │    │    libtrustauthority_      |    |    |
|    |    |    token_verifier.so       │    │    │
│    │    └────────────────────────────┘    │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│             NVIDIA H100 GPU Host               │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the NVGPU example while running within a Docker container. The NVGPU example can also be run directly on a NVIDIA H100 host.

## Prerequisites

- Ability to build the Intel Trust Authority Attestation Client (see [Build Instructions](../../docs/builds.md)).
- A *production* NVGPU host with the NVIDIA driver and Docker installed.
- The NVGPU host must be able to generate GPU evidence with CC_mode enabled.
- NVIDIA container toolkit Installed (see [NVIDIA Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html))


## Build Instructions

Build the NVGPU Token docker image in release/debug mode under `trustauthority-client` home folder.

To build the example in release mode, run the following command. 
```shell
make nvgpu_token_docker
```

To build the example in debug mode, run the following command.
```shell
make DEBUG=1 nvgpu_token_docker
```

When successfully built, running `docker image ls -a` includes `taas/nvgpu_token:v1.x.x`.

## Deployment Instructions
The docker image must be present on the NVGPU host.  For example, it can be exported from a build machine as follows.

```shell
#Save the nvgpu_token Docker image into trust_authority.nvgpu_token.tar.gz
docker save taas/nvgpu_token:v1.x.x > trust_authority.nvgpu_token.tar.gz
#scp trust_authority.nvgpu_token.tar.gz to the nvgpu host.
#On the nvgpu host load/import trust_authority.nvgpu_token.tar.gz docker image using below command
docker load -i trust_authority.nvgpu_token.tar.gz
```

## Running the example

The example requires an environment file to provide the API key and other information. The following table lists the environment variables used in `nvgpu_token.env`.

|Variable			|Description							|
|:--------------------------|:------------------------------------|
|TRUSTAUTHORITY_API_KEY	|The Intel Trust Authority API key.				|
|TRUSTAUTHORITY_API_URL	|The Intel Trust Authority API URL.				|
|TRUSTAUTHORITY_POLICY_ID	|The policy id created using Intel Trust Authority portal.	|
|TRUSTAUTHORITY_BASE_URL	|The base url of Intel Trust Authority certificate management authority to download certificate to verify token in Azure. (ex. 'https://portal.trustauthority.intel.com')|
|REQUEST_ID			|An optional parameter to trace the request.			|
|TOKEN_SIGNING_ALG|An optional parameter to specify token signing algorithm, supported algorithms are RS256, PS384.|
|POLICY_MUST_MATCH|An optional boolean parameter to enforce policies match during attestation, supported values are true/false.|
|RETRY_WAIT_TIME		|Wait time between retries. Default value is 2 seconds.		|
|RETRY_MAX			|Maximum number of retries. Default value is 2 seconds.		|

The API_URL and BASE_URL depend on your location. There are two Intel Trust Authority deployment regions: European Union (EU) region, and a global region for all other countries. There is a different BaseUrl and ApiUrl for each region, as follows:

| Region | BASE_URL | API_URL |
|--- | --- | --- |
| **EU** | `https://portal.eu.trustauthority.intel.com` | `https://api.eu.trustauthority.intel.com` |
| **World/US** | `https://portal.trustauthority.intel.com` | `httsp://api.trustauthority.intel.com` |

1. Create nvgpu_token.env by running the following command. Replace values in <> with your values. Note that if you're in the EU, you also have a different API_URL and BASE_URL as listed above.

```shell
cat <<EOF | tee nvgpu_token.env
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
TRUSTAUTHORITY_API_URL=https://api.trustauthority.intel.com
TRUSTAUTHORITY_BASE_URL=https://portal.trustauthority.intel.com
EOF
```

2. Run the example in a Docker container
```shell
sudo docker run --privileged -v /sys/kernel/config:/sys/kernel/config --rm --runtime=nvidia --gpus all --env-file nvgpu_token.env taas/nvgpu_token:v1.x.x
```

When successful, the token and other information will be displayed.
