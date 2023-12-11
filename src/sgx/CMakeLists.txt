cmake_minimum_required(VERSION 3.10)

project(trustauthority_sgx)

include_directories(
        ../../include
        ../log
)

add_library(${PROJECT_NAME}
    sgx_adapter.c
)

