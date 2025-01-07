cmake_minimum_required(VERSION 3.10)

project(nvgpu_token)

IF(USE_AZURE_TDX_ADAPTER MATCHES ON)
	add_definitions(-DAZURE_TDX=1)
ENDIF()

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} nvgpu_token.c)

include_directories(${CMAKE_SOURCE_DIR}/include
			    ${CMAKE_SOURCE_DIR}/src/log
				${CMAKE_SOURCE_DIR}/src/connector
				${OPENSSL_INCLUDE_DIR}
				)

target_link_libraries(${PROJECT_NAME} PUBLIC
					trustauthority_connector
					trustauthority_nvgpu
					trustauthority_token_verifier
					trustauthority_evidence_builder
					trustauthority_connector
					dl
					curl
					${OPENSSL_LIBRARIES})

IF(USE_AZURE_TDX_ADAPTER MATCHES ON)
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_tdx_azure)
ELSE()
	target_link_libraries(${PROJECT_NAME} PUBLIC
		trustauthority_tdx)
ENDIF()