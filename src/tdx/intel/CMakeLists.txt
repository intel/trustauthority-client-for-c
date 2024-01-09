cmake_minimum_required(VERSION 3.10)

project(trustauthority_tdx)

add_library(${PROJECT_NAME}
    tdx_adapter.c
    ../../log/log.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto tdx_attest)
