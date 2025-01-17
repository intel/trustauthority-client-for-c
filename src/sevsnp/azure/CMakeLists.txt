cmake_minimum_required(VERSION 3.10)

project(trustauthority_sevsnp_azure)

include_directories(../../connector
                    ../../util)

add_library(${PROJECT_NAME}
    azure_sevsnp_adapter.c
    ../../log/log.c
    ../../util/json.c
    ../../util/cleanup.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto tss2-esys)