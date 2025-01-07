cmake_minimum_required(VERSION 3.10)

project(trustauthority_evidence_builder)

add_library(${PROJECT_NAME}
    evidence_builder.c 
    ../log/log.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC jansson)
