cmake_minimum_required(VERSION 3.10)

project(trustauthority_client)

#Generate sgx mock DCAP library
add_library(mocksgxdcap SHARED mock_sgx_dcap/mock_sgx.c)

# Generate mock NVML library for nvgpu_adapter unit tests
add_library(mocknvml SHARED mock_nvml/mock_nvml.c)
target_include_directories(mocknvml PUBLIC mock_nvml/include)

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
    ../src/connector/appraisal_request.c
    ../src/connector/rest.c
    ../src/util/json.c
    ../src/util/base64.c
    ../src/util/cleanup.c
    ../src/configfs_tsm/report.c
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
    report_test.cpp
)

# nvgpu_adapter test — compiled separately to use mock NVML instead of real nvidia-ml
set(NVGPU_TEST_SOURCES
    ../src/log/log.c
    ../src/util/base64.c
    ../src/util/json.c
    ../src/nvgpu/nvgpu_adapter.c
    nvgpu_adapter_test.cpp
)
add_executable(nvgpu_adapter_test ${NVGPU_TEST_SOURCES})
target_compile_definitions(nvgpu_adapter_test PRIVATE TEST_MODE)
find_package(OpenSSL REQUIRED)
target_link_libraries(nvgpu_adapter_test PUBLIC
    ${GTEST_BOTH_LIBRARIES}
    jansson
    mocknvml
    OpenSSL::SSL OpenSSL::Crypto
    pthread
)
target_include_directories(nvgpu_adapter_test PRIVATE
    ../include
    ../src/log
    ../src/util
    mock_nvml/include
)
add_test(NAME nvgpu_adapter_test COMMAND nvgpu_adapter_test)

# Create the test target and link against the Google Test library
add_executable(trustauthorityclienttest ${TEST_SOURCES})
target_compile_definitions(trustauthorityclienttest PRIVATE TEST_MODE)
find_package(CURL REQUIRED)
target_link_libraries(trustauthorityclienttest PUBLIC ${GTEST_BOTH_LIBRARIES} jansson jwt CURL::libcurl -lcurl mocksgxdcap -lssl -lcrypto pthread -lcpprest)
target_include_directories(trustauthorityclienttest PRIVATE
    ../include
    ../src/log
    jansson/src
    jansson/android
    ../src/connector
    ../src/util
    ../src/token_verifier
    ../src/configfs_tsm
    mock_sgx_dcap/include
)

# Add a test target
enable_testing()
add_test(NAME trustauthorityclienttest COMMAND trustauthorityclienttest)
