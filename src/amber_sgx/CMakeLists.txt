cmake_minimum_required(VERSION 3.10)

project(AmberSgx)

include_directories(../../include)

add_library(${PROJECT_NAME} SHARED
    sgx_adapter.c
)