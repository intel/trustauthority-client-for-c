cmake_minimum_required(VERSION 3.10)

project(trustauthority_client)

IF(CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DENABLE_DEBUG_LOGGING=1)
ENDIF()

option (BUILD_EXAMPLES "Build example projects." OFF)
option (BUILD_TESTS "Build test projects." OFF)

include_directories(include src/connector src/log)

add_subdirectory(src)

IF(BUILD_EXAMPLES MATCHES ON)
add_subdirectory(examples)
ENDIF()

IF(BUILD_TESTS MATCHES ON)
add_subdirectory(tests)
ENDIF()
