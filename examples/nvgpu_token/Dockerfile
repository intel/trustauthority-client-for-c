# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
ARG VERSION=v0.0.0
ARG COMMIT=fffffff

FROM ubuntu:24.04 as build
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG
ARG USE_AZURE_TDX_ADAPTER=OFF
RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg wget curl git autoconf automake libtool openssl pkg-config cmake libssl-dev libjansson-dev ca-certificates  libgnutls28-dev build-essential uuid-dev

###########
WORKDIR /
RUN git clone https://github.com/benmcollins/libjwt.git 
WORKDIR /libjwt 
RUN git checkout v1.17.0 && autoreconf -i && ./configure --without-openssl && make all && make install
##########

RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
RUN dpkg -i cuda-keyring_1.1-1_all.deb

WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4-openssl-dev \
    cuda-nvml-dev-12-5 \
    cmake 
WORKDIR /trustauthority-client/
COPY . .
RUN rm -rf build/ 2> /dev/null || true; rm CMakeCache.txt 2> /dev/null || true
WORKDIR /trustauthority-client/build
RUN apt-get install -y --no-install-recommends libssl-dev
RUN cmake -DBUILD_EXAMPLES=ON -DBUILD_NVGPU=ON -DBUILD_TDX=ON -DUSE_AZURE_TDX_ADAPTER=$USE_AZURE_TDX_ADAPTER -DCMAKE_BUILD_TYPE=$ENABLE_DEBUG .. \
    && cmake --build .  --target nvgpu_token

FROM ubuntu:24.04 as nvgpu_token_cont
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
    apt-get install -y --no-install-recommends apt-utils gnupg ca-certificates curl

RUN apt-get autoremove -y

RUN apt-get update && apt-get install -y --no-install-recommends libjansson4 libcurl4 openssl \
    uuid-dev

WORKDIR /nvgpu_token
COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /trustauthority-client/build/examples/nvgpu_token/nvgpu_token .
USER $USERNAME
CMD ["env",  "LD_LIBRARY_PATH=/nvgpu_token", "./nvgpu_token"]
