
# Unit Test Build Instructions

<p style="font-size: 0.875em;">· 17 January 2025 ·</p>

Intel® Trust Authority Client for C unit tests are based on the [GoogleTest](https://github.com/google/googletest#) framework.  

## Supported Operating Systems

The table below lists the Linux distributions that the build process currently supports.

    |Distribution	|Build Target Name	|
    |:--------------|:--------------|
    |Ubuntu 20.04	| ubuntu_20	   	|
    |RHEL 8.x	 	| NA			|

## Build instructions

1. Copy and run the following commands to install dependencies:

```shell
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    cmake \
    g++ \
    lcov \
    autoconf \
    automake \
    libtool \
    libcurl4-openssl-dev \
    libssl-dev \
    git \
    libcpprest-dev \
    libjansson-dev=2.12-1build1 \ 
    build-essential \ 
    ca-certificates \
    googletest \
    pkg-config \
    libgtest-dev

# Set CXX=/usr/bin/g++
export CXX=/usr/bin/g++
```

2. Install libjwt:

```shell
git clone https://github.com/benmcollins/libjwt.git && cd libjwt && git checkout v1.17.0  
autoreconf -i && ./configure --without-openssl && make all && make install  
```

3. Build unit test and get the coverage by running coverage tool

```shell
# Go to the directory containing test files to be built
cd tests
# Create a build folder inside that
mkdir build  && cd build  
cmake ..  
cmake --build .  

#It will produce the test application named `trustauthorityclienttest` to run the test cases.
#Now run the generated executable. 
./trustauthorityclienttest

#Coverage files will be generated inside - CMakeFiles/trustauthorityclienttest.dir
#Run the following command to generate overall coverage.info file. 
lcov -o coverage.info -c -d CMakeFiles/trustauthorityclienttest.dir

#Now filter only the required coverage information of the source test files. 
lcov --extract coverage.info 'path/to/required/folder/*' --output-file filtered_coverage.info

#Note : (*) is must at the end of the path and always give absolute path in path to required folder
#Get the coverage percentage of each file on console: 
lcov --list filtered_coverage.info
```
