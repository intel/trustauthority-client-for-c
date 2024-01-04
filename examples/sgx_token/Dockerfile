# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
ARG VERSION=v0.0.0
ARG COMMIT=fffffff
ARG DCAP_VERSION=0.0
ARG PSW_VERSION=0.0

FROM ubuntu:20.04 as build
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG
ARG DCAP_VERSION
ARG PSW_VERSION
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg wget curl git autoconf automake libtool openssl pkg-config cmake libssl-dev libjansson-dev=2.12-1build1 ca-certificates
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key
RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential
WORKDIR /opt/intel
RUN wget -q https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu20.04-server/sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    chmod +x sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    echo 'yes' | ./sgx_linux_x64_sdk_${PSW_VERSION}.bin

##TODO - Below lines need to be removed upon libjwt release
###########
WORKDIR /
RUN git clone https://github.com/benmcollins/libjwt.git
WORKDIR /libjwt 
RUN git checkout c276dc7 && autoreconf -i && ./configure && make all && make install
##########

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-urts=${PSW_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION} \
    libsgx-pce-logic=${DCAP_VERSION} \
    libsgx-dcap-ql=${DCAP_VERSION} \
    libsgx-dcap-ql-dev=${DCAP_VERSION} \
    libcurl4-openssl-dev \
    cmake 
WORKDIR /trustauthority-client/
COPY . .
WORKDIR /trustauthority-client/minimal-enclave
RUN make clean all
RUN cp /trustauthority-client/minimal-enclave/Enclave_u.* /trustauthority-client/examples/sgx_token/
WORKDIR /trustauthority-client/build
RUN cmake -DBUILD_EXAMPLES=ON -DBUILD_SGX=ON -DCMAKE_BUILD_TYPE=$ENABLE_DEBUG .. \
    && cmake --build .  --target sgx_token


FROM ubuntu:20.04 as sgx_token_cont
ARG MAKEFILE_DIR
ARG DEBIAN_FRONTEND=noninteractive
ARG DCAP_VERSION
ARG PSW_VERSION
ARG USERNAME=intel
ARG USER_UID=2000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME


RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends apt-utils gnupg ca-certificates curl
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key
RUN apt-get autoremove -y
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsgx-urts=${PSW_VERSION}-focal1 \
        libsgx-dcap-ql=${DCAP_VERSION} \
        libsgx-qe3-logic=${DCAP_VERSION} \
        libsgx-pce-logic=${DCAP_VERSION} \
        libsgx-dcap-default-qpl=${DCAP_VERSION} \
	libsgx-quote-ex=${PSW_VERSION}-focal1
	#libjwt-dev

RUN apt-get install -y --no-install-recommends libjansson4=2.12-1build1 libcurl4 libssl1.1

WORKDIR /sgx_token
COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /trustauthority-client/minimal-enclave/enclave.signed.so .
COPY --from=build /trustauthority-client/minimal-enclave/libutils.so .
COPY --from=build /trustauthority-client/bin/ubuntu_20/libtrustauthority_connector.a .
COPY --from=build /trustauthority-client/bin/ubuntu_20/libtrustauthority_token_provider.a .
COPY --from=build /trustauthority-client/bin/ubuntu_20/libtrustauthority_token_verifier.a .
COPY --from=build /trustauthority-client/bin/ubuntu_20/libtrustauthority_sgx.a .
COPY --from=build /trustauthority-client/build/examples/sgx_token/sgx_token .
USER $USERNAME
CMD ["env",  "LD_LIBRARY_PATH=/sgx_token:/usr/local/lib/", "./sgx_token"]
