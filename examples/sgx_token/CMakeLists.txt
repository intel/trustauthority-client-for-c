cmake_minimum_required(VERSION 3.10)

project(sgx_token)

include_directories(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/examples/sgx_enclave)

link_directories(${CMAKE_SOURCE_DIR}/examples/sgx_enclave)

add_executable(${PROJECT_NAME} sgx_token.c
                               enclave.c)

# TODO:  Amber Client has a dependency on libcurl (statically link?)
target_link_libraries(${PROJECT_NAME} PUBLIC 
                        AmberApi
                        AmberTokenProvider
                        AmberTokenVerifier
                        app
                        curl)
