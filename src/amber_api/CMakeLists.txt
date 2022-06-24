cmake_minimum_required(VERSION 3.10)

project(AmberApi)

SET(JANSSON_BUILD_DOCS OFF CACHE BOOL "Build documentation (uses python-sphinx).")

add_subdirectory(jansson)

add_library(${PROJECT_NAME} SHARED
    api.c
    json.c
    rest.c
    base64.c
)

# TASK:  Add gtest

target_include_directories(${PROJECT_NAME} PRIVATE
    ../../include
    ../log
    jansson/src
    jansson/android
)

target_link_libraries(${PROJECT_NAME} PUBLIC jansson)
