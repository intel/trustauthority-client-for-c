cmake_minimum_required(VERSION 3.10)

project(trustauthority_tdx_azure)

include_directories(../../connector)

add_library(${PROJECT_NAME}
    azure_tdx_adapter.c
    ../../log/log.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto tss2-esys)
