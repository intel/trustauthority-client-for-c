FROM ubuntu:20.04
ARG MAKEFILE_DIR
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y gnupg wget
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update && apt-get install -y --no-install-recommends \
        libtdx-attest \
        libcurl4-openssl-dev
WORKDIR /tdx_token
COPY bin/ubuntu_20/libAmberApi.so .
COPY bin/ubuntu_20/libAmberTdx.so .
COPY bin/ubuntu_20/libAmberTokenVerifier.so .
COPY bin/ubuntu_20/libAmberTokenProvider.so .
COPY bin/ubuntu_20/tdx_token .
COPY examples/tdx_token/run.sh .
CMD ["/tdx_token/run.sh"]
