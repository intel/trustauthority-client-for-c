cmake_minimum_required(VERSION 3.10)

project(trustauthority_nvgpu)

add_library(${PROJECT_NAME}
    nvgpu_adapter.c
    ../log/log.c
    ../util/json.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../../include
    ../util
)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NVIDIA_ML REQUIRED nvidia-ml-12.5)

link_directories(${NVIDIA_ML_LIBRARY_DIRS})

include_directories(${OPENSSL_INCLUDE_DIRS} ${NVIDIA_ML_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${NVIDIA_ML_LINK_LIBRARIES})
