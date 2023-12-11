cmake_minimum_required(VERSION 3.10)

project(trustauthority_tdx)

include_directories(../../include
                    ../log)

add_library(${PROJECT_NAME}
    tdx_adapter.c
)

target_link_libraries(${PROJECT_NAME} PUBLIC tdx_attest -lssl -lcrypto)
