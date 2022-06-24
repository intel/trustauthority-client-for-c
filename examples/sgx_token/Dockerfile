FROM ubuntu:20.04
ARG MAKEFILE_DIR
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y gnupg wget
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsgx-urts \
        libsgx-dcap-ql \
        libsgx-dcap-default-qpl
WORKDIR /sgx_token
COPY bin/ubuntu_20/enclave.signed.so .
COPY bin/ubuntu_20/libapp.so .
COPY bin/ubuntu_20/libAmberApi.so .
COPY bin/ubuntu_20/libAmberTokenVerifier.so .
COPY bin/ubuntu_20/libAmberTokenProvider.so .
COPY bin/ubuntu_20/sgx_token .
COPY examples/sgx_token/run.sh .
CMD ["/sgx_token/run.sh"]
