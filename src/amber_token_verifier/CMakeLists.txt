cmake_minimum_required(VERSION 3.10)

project(AmberTokenVerifier)

add_library(${PROJECT_NAME} SHARED
    token_verifier.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ../../include
    ../log
)
