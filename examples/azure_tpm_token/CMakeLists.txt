cmake_minimum_required(VERSION 3.10)

project(azure_tpm_token)

add_definitions(-DAZURE_TPM=1)

IF(USE_AZURE_SEVSNP_ADAPTER MATCHES ON)
	add_definitions(-DAZURE_SEVSNP=1)
ENDIF()

include_directories(${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/src/log
	${CMAKE_SOURCE_DIR}/src/connector)

add_executable(${PROJECT_NAME} azure_tpm_token.c)

target_link_libraries(${PROJECT_NAME} PUBLIC 
	trustauthority_connector
	trustauthority_token_verifier
	trustauthority_evidence_builder
	trustauthority_tpm
	curl)

IF(USE_AZURE_SEVSNP_ADAPTER MATCHES ON)
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_sevsnp_azure)
ELSE()
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_tdx_azure)
ENDIF()
