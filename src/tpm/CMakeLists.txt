cmake_minimum_required(VERSION 3.10)

project(trustauthority_tpm)

include_directories(../connector
                    ../util)

add_library(${PROJECT_NAME}
    tpm_adapter.c
    ../log/log.c
    ../util/json.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto tss2-esys
    tss2-tctildr
    tss2-tcti-device
    tss2-mu)