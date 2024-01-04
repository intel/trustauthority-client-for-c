option (BUILD_SGX "Build SGX adapter." OFF)
option (BUILD_TDX "Build TDX adapter." OFF)

add_subdirectory(connector)
add_subdirectory(token_provider)
add_subdirectory(token_verifier)

if (${BUILD_SGX})
add_subdirectory(sgx)
endif()

if (${BUILD_TDX})
add_subdirectory(tdx)
endif()