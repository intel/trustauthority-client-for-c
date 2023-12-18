# Build Instructions
Intel Trust Authority Client unit tests are based on Googletest framework.  

## Instructions
- The table below lists the Linux distributions that the build process currently supports.

    |Distribution	|Build Target Name	|
    |:------------------|:----------------------|
    |Ubuntu 20.04	| ubuntu_20	   	|
    |RHEL 8.x	 	| NA			|

## Install Unit test dependencies

```shell
apt-get update &&  apt-get install -y --no-install-recommends \
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

#Set CXX=/usr/bin/g++
export CXX=/usr/bin/g++
```

## Install libjwt 
```shell
git clone https://github.com/benmcollins/libjwt.git && cd libjwt && git checkout c276dc7 && autoreconf -i  
cd libjwt && ./configure && make all && make install  
```

## Build unit test and get the coverage by running coverage tool

```shell
# Go the directory containing test files to be built
cd tests
# Create a build folder inside that
mkdir build
cd build  
cmake ..  
cmake --build .  


#It will produce the test application named `trustauthorityclienttest` to run the test cases.
#Now run the generated executable. 

./trustauthorityclienttest

#Gcoverage files will be generated inside - CMakeFiles/trustauthorityclienttest.dir
#Run the below command to generate overall coverage.info file  - lcov -o coverage.info -c -d <directory_with_gcoverage_files>`  
lcov -o coverage.info -c -d CMakeFiles/trustauthorityclienttest.dir

#Now filter only the required coverage information of the source test files. 
lcov --extract coverage.info 'path/to/required/folder/*' --output-file filtered_coverage.info

#Example : lcov --extract coverage.info '/<ita-clone-path>/src/*' --output-file filtered_coverage.info

#Note : (*) is must at the end of the path and always give absolute path in path to required folder
#Get the coverage percentage of each file on console: 

lcov --list filtered_coverage.info
```
