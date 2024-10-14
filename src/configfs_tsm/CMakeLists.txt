cmake_minimum_required(VERSION 3.10)

project(trustauthority_configfs_tsm)

add_library(${PROJECT_NAME}
    report.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)
