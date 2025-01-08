# Build Instructions
The Intel Trust Authority Client build process uses Docker and produces libraries in the /bin directory. 

## Prerequisites
- Docker v20+
- make   

## Instructions
- The table below lists the Linux distributions that the build process currently supports.


    |Distribution	|Build Target Name	|
    |:------------------|:----------------------|
    |Ubuntu 20.04	| ubuntu_20	   	|
    |RHEL 8.x	 	| NA			|

```shell
#Below command will produce static libraries in release mode inside bin\ubuntu_20
make ubuntu_20

#Below command will produce static libraries in debug mode inside bin\ubuntu_20
make DEBUG=1 ubuntu_20 
```

## Prerequistes to build connector library from src without using docker in ubuntu 20.04 build system 
```shell
#Install sgx repo
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list  
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -  

#create the workdir
mkdir /opt/intel  

#Install sgx sdk
wget -q https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.22.100.3.bin;  \  
    chmod +x sgx_linux_x64_sdk_2.22.100.3.bin; \  
    echo 'yes' | ./sgx_linux_x64_sdk_2.22.100.3.bin  

#Install other dependencies like sgx dcap and others
apt-get update && apt-get install -y --no-install-recommends \  
    libsgx-urts=2.22.100.3-focal \  
    libsgx-qe3-logic=1.19.100.3-focal1 \  
    libsgx-pce-logic=1.19.100.3-focal1 \  
    libsgx-dcap-default-qpl=1.19.100.3-focal1 \  
    libsgx-dcap-ql=1.19.100.3-focal1 \  
    libsgx-dcap-ql-dev=1.19.100.3-focal1 \
    cmake \
    libcurl4-openssl-dev \
    libjansson-dev=2.12-1build1 \
    pkg-config \
    libtool \
    automake \
    autoconf \
    gnupg \
    libssl-dev \
    libtss2-dev \
    git \  
    build-essential   

#Install libjwt 
git clone https://github.com/benmcollins/libjwt.git && cd libjwt && git checkout v1.17.0  
autoreconf -i && ./configure --without-openssl && make all && make install  

#Example Build : src/connector library  
mkdir build  && cd build
#For building Static libraries use
cmake ..  
cmake --build .
#For building Shared libraries use
cmake .. -DBUILD_SHARED_LIBS=true
cmake --build .
```
