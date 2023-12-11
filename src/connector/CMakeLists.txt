cmake_minimum_required(VERSION 3.10)

project(trustauthority_connector)

SET(JANSSON_BUILD_DOCS OFF CACHE BOOL "Build documentation (uses python-sphinx).")

# Clone jansson repo
#file(REMOVE_RECURSE ${CMAKE_CURRENT_SOURCE_DIR}/jansson )

execute_process (
    COMMAND sudo apt-get install -y libjansson-dev
    COMMAND bash -c "git clone https://github.com/benmcollins/libjwt.git && cd libjwt && git checkout c276dc7 && autoreconf -i && ./configure && make all && sudo make install"

    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE outVar
)

add_library(${PROJECT_NAME}
    connector.c 
    api.h
    rest.c
    rest.h
    json.c
    json.h
    base64.c
    ../log/log.c
    base64.h
    appraisal_request.h
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ../../include
    ../log
)

target_link_libraries(${PROJECT_NAME} PUBLIC jansson jwt -lssl -lcrypto)
