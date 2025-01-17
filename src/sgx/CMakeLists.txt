cmake_minimum_required(VERSION 3.10)

project(trustauthority_sgx)

include_directories(../util)

add_library(${PROJECT_NAME}
    sgx_adapter.c
    ../log/log.c
    ../util/json.c
    ../util/cleanup.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC sgx_dcap_ql)
