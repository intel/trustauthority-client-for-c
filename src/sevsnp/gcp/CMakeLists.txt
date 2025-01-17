cmake_minimum_required(VERSION 3.10)

project(trustauthority_sevsnp)

include_directories(../../configfs_tsm
                    ../../util)

add_library(${PROJECT_NAME}
    sevsnp_adapter.c
    ../../log/log.c
    ../../util/json.c
    ../../util/cleanup.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC crypto trustauthority_configfs_tsm)