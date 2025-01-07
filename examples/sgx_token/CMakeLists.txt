cmake_minimum_required(VERSION 3.10)

project(sgx_token)

include_directories(${CMAKE_SOURCE_DIR}/include
		            ${CMAKE_SOURCE_DIR}/src/log
		            ${CMAKE_SOURCE_DIR}/src/connector
		            ${CMAKE_SOURCE_DIR}/minimal-enclave
		            /opt/intel/sgxsdk/include)

link_directories(${CMAKE_SOURCE_DIR}/minimal-enclave)

add_executable(${PROJECT_NAME} sgx_token.c Enclave_u.c)

target_link_libraries(${PROJECT_NAME} PUBLIC
			            trustauthority_connector
			            trustauthority_sgx
			            trustauthority_token_verifier
			            trustauthority_evidence_builder
			            sgx_dcap_ql
			            sgx_urts
			            dl
			            utils
			            curl)
