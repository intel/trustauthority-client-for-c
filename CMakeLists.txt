cmake_minimum_required(VERSION 3.10)

project(trustauthority_client)

IF(CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DENABLE_DEBUG_LOGGING=1)
ENDIF()

add_subdirectory(src/connector)
add_subdirectory(src/token_provider)
add_subdirectory(src/token_verifier)
add_subdirectory(src/tdx)
add_subdirectory(src/sgx)

IF(BUILD_SGX_EXAMPLE MATCHES ON)
add_subdirectory(examples/sgx_token)
ENDIF()

IF(BUILD_TDX_EXAMPLE MATCHES ON)
add_subdirectory(examples/tdx_token)
ENDIF()
