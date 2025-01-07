option (BUILD_SGX "Build SGX example." OFF)
option (BUILD_TDX "Build TDX example." OFF)
option (BUILD_TPM "Build TPM example." OFF)
option (BUILD_SEVSNP "Build SEVSNP example." OFF)
option (BUILD_NVGPU "Build NVGPU example." OFF)

if (${BUILD_SGX})
    add_subdirectory(sgx_token)
endif()

if (${BUILD_TDX})
    add_subdirectory(tdx_token)
endif()

if (${BUILD_TPM})
    add_subdirectory(azure_tpm_token)
endif()
    
if (${BUILD_SEVSNP})
    add_subdirectory(sevsnp_token)
endif()

if (${BUILD_NVGPU})
    add_subdirectory(nvgpu_token)
endif()
