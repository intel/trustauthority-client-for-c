SHELL := /bin/bash
ORGNAME := amber
APPNAME := amber-client
REPO := localhost:5000

COMMIT := $(shell git rev-parse --short HEAD)
VERSION := v0.3.0
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" || "${no_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
    DOCKER_PROXY_FLAGS = --build-arg http_proxy="${http_proxy}" --build-arg https_proxy="${https_proxy}" --build-arg no_proxy="${no_proxy}"
	DOCKER_RUN_PROXY_FLAGS = -e HTTP_PROXY="${http_proxy}" -e HTTPS_PROXY="${https_proxy}" -e NO_PROXY="${no_proxy}"
else
    DOCKER_PROXY_FLAGS =
	DOCKER_RUN_PROXY_FLAGS = 
endif

MAKEFILE_PATH := $(realpath $(lastword $(MAKEFILE_LIST)))
MAKEFILE_DIR := $(dir $(MAKEFILE_PATH))

.PHONY: all ubuntu_20 clean
.DEFAULT: all

all: ubuntu_20

ubuntu_20: 
# mkdir -p ${MAKEFILE_DIR}bin/ubuntu_20
	DOCKER_BUILDKIT=1 docker build \
		${DOCKER_PROXY_FLAGS} \
		-f docker/Dockerfile.ubuntu_20 \
		--output ${MAKEFILE_DIR}bin/ubuntu_20 \
		-t $(ORGNAME)/$(APPNAME)-ubuntu_20:$(VERSION) \
		--build-arg VERSION=${VERSION} \
		--build-arg COMMIT=${COMMIT} .

sgx_token_docker: ubuntu_20
	DOCKER_BUILDKIT=1 docker build \
		${DOCKER_PROXY_FLAGS} \
		-f examples/sgx_token/Dockerfile \
		-t $(ORGNAME)/sgx_token:$(VERSION) \
		--build-arg MAKEFILE_DIR=${MAKEFILE_DIR} \
		--build-arg VERSION=${VERSION} \
		--build-arg COMMIT=${COMMIT} .

tdx_token_docker: ubuntu_20
	DOCKER_BUILDKIT=1 docker build \
		${DOCKER_PROXY_FLAGS} \
		-f examples/tdx_token/Dockerfile \
		-t $(ORGNAME)/tdx_token:$(VERSION) \
		--build-arg MAKEFILE_DIR=${MAKEFILE_DIR} \
		--build-arg VERSION=${VERSION} \
		--build-arg COMMIT=${COMMIT} .

clean:
	rm -rf ${MAKEFILE_DIR}bin


