option (BUILD_SGX "Build SGX example." OFF)
option (BUILD_TDX "Build TDX example." OFF)

if (${BUILD_SGX})
add_subdirectory(sgx_token)
endif()

if (${BUILD_TDX})
add_subdirectory(tdx_token)
endif()