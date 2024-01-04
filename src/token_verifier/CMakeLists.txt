cmake_minimum_required(VERSION 3.10)

project(trustauthority_token_verifier)

add_library(${PROJECT_NAME}
    token_verifier.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC trustauthority_connector)
