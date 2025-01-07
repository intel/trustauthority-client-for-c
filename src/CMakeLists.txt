option (BUILD_SGX "Build SGX adapter." OFF)
option (BUILD_TDX "Build TDX adapter." OFF)
option (BUILD_TPM "Build TPM adapter." OFF)
option (BUILD_SEVSNP "Build SEVSNP adapter." OFF)
option (BUILD_NVGPU "Build NVGPU adapter." OFF)

add_subdirectory(connector)
add_subdirectory(token_provider)
add_subdirectory(token_verifier)
add_subdirectory(configfs_tsm)
add_subdirectory(evidence_builder)

if (${BUILD_SGX})
    add_subdirectory(sgx)
endif()

if (${BUILD_TDX})
    add_subdirectory(tdx)
endif()

if (${BUILD_TPM})
    add_subdirectory(tpm)
endif()

if (${BUILD_SEVSNP})
    add_subdirectory(sevsnp)
endif()

if (${BUILD_NVGPU})
    add_subdirectory(nvgpu)
endif()
