cmake_minimum_required(VERSION 3.10)

project(tdx_token)

IF(USE_AZURE_TDX_ADAPTER MATCHES ON)
	add_definitions(-DAZURE_TDX=1)
ENDIF()

include_directories(${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/src/log
	${CMAKE_SOURCE_DIR}/src/connector)

add_executable(${PROJECT_NAME} tdx_token.c)

target_link_libraries(${PROJECT_NAME} PUBLIC 
	trustauthority_connector
	trustauthority_token_provider
	trustauthority_token_verifier
	trustauthority_configfs_tsm
	curl)

IF(USE_AZURE_TDX_ADAPTER MATCHES ON)
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_tdx_azure)
ELSE()
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_tdx)
ENDIF()
