cmake_minimum_required(VERSION 3.10)

project(tdx_token)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME} tdx_token.c)

# TODO:  Amber Client has a dependency on libcurl (statically link?)
target_link_libraries(${PROJECT_NAME} PUBLIC 
                        AmberApi
                        AmberTdx
                        AmberTokenProvider
                        AmberTokenVerifier
                        curl)
