cmake_minimum_required(VERSION 3.10)

project(AmberTdx)

include_directories(../../include)

add_library(${PROJECT_NAME} SHARED
    tdx_adapter.c
)

target_link_libraries(${PROJECT_NAME} PUBLIC tdx_attest ssl)
