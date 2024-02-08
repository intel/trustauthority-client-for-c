cmake_minimum_required(VERSION 3.10)

project(trustauthority_tdx_azure)

include_directories(../../../include
                    ../../connector
                    ../../log)

add_library(${PROJECT_NAME}
    azure_tdx_adapter.c
)

target_link_libraries(${PROJECT_NAME} PUBLIC -lssl -lcrypto -ltss2-esys)
