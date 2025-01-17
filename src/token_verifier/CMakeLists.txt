cmake_minimum_required(VERSION 3.10)

project(trustauthority_token_verifier)

include_directories(../connector
                    ../util)

add_library(${PROJECT_NAME}
    token_verifier.c
    util.c
    ../util/cleanup.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC trustauthority_connector)
