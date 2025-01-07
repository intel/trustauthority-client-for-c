cmake_minimum_required(VERSION 3.10)

project(trustauthority_connector)

execute_process (
    COMMAND sudo apt-get install -y libjansson-dev libgnutls28-dev
    COMMAND bash -c "git clone https://github.com/benmcollins/libjwt.git && cd libjwt && git checkout v1.17.0 && autoreconf -i && ./configure --without-openssl && make all && sudo make install"

    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE outVar
)

include_directories(../util)

add_library(${PROJECT_NAME}
    connector.c 
    rest.c
    appraisal_request.c
    ../util/json.c
    ../util/base64.c
    ../log/log.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
)

target_link_libraries(${PROJECT_NAME} PUBLIC jansson jwt crypto curl)
