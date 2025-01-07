cmake_minimum_required(VERSION 3.10)

project(azure_tpm_token)

add_definitions(-DAZURE_TPM=1)

include_directories(${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/src/log
	${CMAKE_SOURCE_DIR}/src/connector)

add_executable(${PROJECT_NAME} azure_tpm_token.c)

target_link_libraries(${PROJECT_NAME} PUBLIC 
	trustauthority_connector
	trustauthority_token_verifier
	trustauthority_evidence_builder
	trustauthority_tdx_azure
	trustauthority_tpm
	curl)

