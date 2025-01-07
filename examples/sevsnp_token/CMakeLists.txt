cmake_minimum_required(VERSION 3.10)

project(sevsnp_token)

IF(USE_AZURE_SEVSNP_ADAPTER MATCHES ON)
	add_definitions(-DAZURE_SEVSNP=1)
ENDIF()

include_directories(${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/src/log
	${CMAKE_SOURCE_DIR}/src/connector)

add_executable(${PROJECT_NAME} sevsnp_token.c)

target_link_libraries(${PROJECT_NAME} PUBLIC 
	trustauthority_connector
	trustauthority_token_verifier
	trustauthority_evidence_builder
	curl)

IF(USE_AZURE_SEVSNP_ADAPTER MATCHES ON)
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_sevsnp_azure)
ELSE()
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_configfs_tsm
		trustauthority_sevsnp)
ENDIF()