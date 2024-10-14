# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
ARG VERSION=v0.0.0
ARG COMMIT=fffffff

FROM ubuntu:20.04 as build
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG
ARG USE_AZURE_TDX_ADAPTER
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends git \
    autoconf \
    automake \
    libtool \
    openssl \
    libssl-dev \
    pkg-config \
    cmake \
    libjansson-dev=2.12-1build1 \
    build-essential \
    autoconf-archive \
    libltdl-dev \
    libjson-c-dev \
    libcurl4-openssl-dev \
    uuid-dev \
    tpm2-tools=4.1.1-1ubuntu0.20.04.1 \
    ca-certificates \
    apt-utils \
    gnupg \
    curl \
    libgnutls28-dev

##TODO - Below lines need to be removed upon libjwt release
###########
WORKDIR /
RUN git clone https://github.com/benmcollins/libjwt.git 
WORKDIR /libjwt 
RUN git checkout v1.17.0 && autoreconf -i && ./configure --without-openssl && make all && make install
##########

WORKDIR /
RUN git clone https://github.com/tpm2-software/tpm2-tss.git
WORKDIR /tpm2-tss
RUN git checkout 4.0.1 && ./bootstrap && ./configure && make install

RUN apt-get update && apt-get install -y --no-install-recommends \
	libjansson4=2.12-1build1 \ 
	libcurl4 \
	libssl1.1
	#libjwt-dev    

WORKDIR /trustauthority-client/
COPY . .
WORKDIR /trustauthority-client/build 
RUN cmake -DBUILD_EXAMPLES=ON -DBUILD_TDX=ON -DCMAKE_BUILD_TYPE=$ENABLE_DEBUG -DUSE_AZURE_TDX_ADAPTER=${USE_AZURE_TDX_ADAPTER} .. \
    && cmake --build . --target tdx_token

FROM ubuntu:20.04 as intel_tdx_token
ARG MAKEFILE_DIR
##AMI - below line needs to be removed
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends apt-utils gnupg ca-certificates curl \
    libjansson4=2.12-1build1 \ 
    libcurl4 \
    libssl1.1

WORKDIR /tdx_token

COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /trustauthority-client/build/examples/tdx_token/tdx_token .
CMD ["env",  "LD_LIBRARY_PATH=/tdx_token:/usr/local/lib/", "./tdx_token"]

FROM ubuntu:20.04 as azure_tdx_token
ARG MAKEFILE_DIR
ARG DCAP_PKG_VERSION
ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=intel
ARG USER_UID=2000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends tpm2-tools=4.1.1-1ubuntu0.20.04.1 \
    curl \
    libjansson4=2.12-1build1 \
    ca-certificates
    
WORKDIR /tdx_token

COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /usr/local/lib/libtss2_esys* /usr/local/lib/
COPY --from=build /trustauthority-client/build/examples/tdx_token/tdx_token .
USER $USERNAME
CMD ["env",  "LD_LIBRARY_PATH=/tdx_token:/usr/local/lib/", "./tdx_token"]