# Copyright (C) 2025-2026 Intel Corporation
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
    apt-get install -y --no-install-recommends \
        gnupg wget curl git autoconf automake libtool cmake \
        libssl-dev libjansson-dev libcurl4-openssl-dev libgnutls28-dev \
        ca-certificates build-essential uuid-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /
RUN git clone https://github.com/benmcollins/libjwt.git
WORKDIR /libjwt
RUN git checkout v1.17.0 && autoreconf -i && ./configure --without-openssl && make all && make install

RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
RUN dpkg -i cuda-keyring_1.1-1_all.deb

WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends \
    cuda-nvml-dev-13-1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /trustauthority-client/
COPY . .
RUN rm -rf build/ 2> /dev/null || true; rm CMakeCache.txt 2> /dev/null || true
WORKDIR /trustauthority-client/build
RUN cmake -DBUILD_EXAMPLES=ON -DBUILD_NVGPU=ON -DBUILD_TDX=ON -DUSE_AZURE_TDX_ADAPTER=$USE_AZURE_TDX_ADAPTER -DCMAKE_BUILD_TYPE=$ENABLE_DEBUG .. \
    && cmake --build .  --target nvgpu_token


FROM ubuntu:24.04 as nvgpu_token
ARG MAKEFILE_DIR
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        libjansson4 libcurl4 libgnutls30 openssl ca-certificates && \
    apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /nvgpu_token
COPY --from=build /usr/local/lib/libjwt* /usr/local/lib/
COPY --from=build /trustauthority-client/build/examples/nvgpu_token/nvgpu_token .
CMD ["env", "LD_LIBRARY_PATH=/nvgpu_token:/usr/local/lib/", "./nvgpu_token"]
