cmake_minimum_required(VERSION 3.10)

project(trustauthority_tdx)

include_directories(../../configfs_tsm
                    ../../util)

add_library(${PROJECT_NAME}
    tdx_adapter.c
    ../../log/log.c
    ../../util/json.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto trustauthority_configfs_tsm)
