cmake_minimum_required(VERSION 3.10)

project(tdx_token)

include_directories(${CMAKE_SOURCE_DIR}/include
		    ${CMAKE_SOURCE_DIR}/src/log)

add_executable(${PROJECT_NAME} tdx_token.c)

target_link_libraries(${PROJECT_NAME} PUBLIC 
                        trustauthority_connector
                        trustauthority_tdx
                        trustauthority_token_provider
                        trustauthority_token_verifier
                        curl)
