cmake_minimum_required(VERSION 3.10)

project(AmberTokenProvider)

add_library(${PROJECT_NAME} SHARED
    token_provider.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ../../include
    ../log
)

target_link_libraries(${PROJECT_NAME} PUBLIC AmberApi
                                             curl)
