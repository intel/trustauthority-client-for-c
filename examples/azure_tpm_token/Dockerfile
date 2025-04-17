# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
ARG VERSION=v0.0.0
ARG COMMIT=fffffff

FROM ubuntu:20.04 as build
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG
ARG USE_AZURE_SEVSNP_ADAPTER
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

RUN apt-get update && apt-get install -y --no-install-recommends \
	libjansson4=2.12-1build1 \ 
	libcurl4 \
	libssl1.1 \
	libtss2-dev
	#libjwt-dev    

WORKDIR /trustauthority-client/
COPY . .
WORKDIR /trustauthority-client/build 
RUN cmake -DBUILD_EXAMPLES=ON -DBUILD_TDX=ON -DBUILD_SEVSNP=ON -DBUILD_TPM=ON -DUSE_AZURE_SEVSNP_ADAPTER=${USE_AZURE_SEVSNP_ADAPTER} -DCMAKE_BUILD_TYPE=$ENABLE_DEBUG .. \
    && cmake --build . --target azure_tpm_token

FROM ubuntu:20.04 as azure_tpm_token
ARG MAKEFILE_DIR
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
    
WORKDIR /azure_tpm_token

COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /usr/local/lib/libtss2_esys* /usr/local/lib/
COPY --from=build /trustauthority-client/build/src/tdx/azure/libtrustauthority_tdx_azure.a .
COPY --from=build /trustauthority-client/build/examples/azure_tpm_token/azure_tpm_token .
USER $USERNAME
CMD ["env",  "LD_LIBRARY_PATH=/azure_tpm_token:/usr/local/lib/", "./azure_tpm_token"]

FROM ubuntu:20.04 as azure_sevsnp_tpm_token
ARG MAKEFILE_DIR
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
    
WORKDIR /azure_tpm_token

COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /usr/local/lib/libtss2_esys* /usr/local/lib/
COPY --from=build /trustauthority-client/build/src/sevsnp/azure/libtrustauthority_sevsnp_azure.a .
COPY --from=build /trustauthority-client/build/examples/azure_tpm_token/azure_tpm_token .
USER $USERNAME
CMD ["env",  "LD_LIBRARY_PATH=/azure_tpm_token:/usr/local/lib/", "./azure_tpm_token"]
