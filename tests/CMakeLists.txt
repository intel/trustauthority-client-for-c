cmake_minimum_required(VERSION 3.10)

project(trustauthority_client)

#Generate sgx mock DCAP library
add_library(mocksgxdcap SHARED mock_sgx_dcap/mock_sgx.c)

# Find the Google Test library
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add the following lines to enable code coverage
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage -g")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")

# Add the test source files
set(TEST_SOURCES
    ../src/log/log.c
    ../src/connector/connector.c
    ../src/connector/rest.c
    ../src/connector/json.c
    ../src/connector/base64.c
    ../src/sgx/sgx_adapter.c
    ../src/tdx/intel/tdx_adapter.c
    ../src/token_provider/token_provider.c
    ../src/token_verifier/token_verifier.c
    ../src/token_verifier/util.c
    base64_test.cpp
    rest_test.cpp
    json_test.cpp
    connector_test.cpp    
    sgx_adapter_test.cpp
    tdx_adapter_test.cpp
    token_provider_test.cpp
    token_verifier_test.cpp
)

# Create the test target and link against the Google Test library
add_executable(trustauthorityclienttest ${TEST_SOURCES})
find_package(CURL REQUIRED)
target_link_libraries(trustauthorityclienttest PUBLIC ${GTEST_BOTH_LIBRARIES} jansson jwt CURL::libcurl -lcurl mocksgxdcap -lssl -lcrypto pthread -lcpprest)
target_include_directories(trustauthorityclienttest PRIVATE
    ../include
    ../src/log
    jansson/src
    jansson/android
    ../src/connector
    ../src/token_verifier
    mock_sgx_dcap/include
)

# Add a test target
enable_testing()
add_test(NAME trustauthorityclienttest COMMAND trustauthorityclienttest)
