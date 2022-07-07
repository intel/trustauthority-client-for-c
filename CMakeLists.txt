cmake_minimum_required(VERSION 3.10)

project(amber_client)

# TODO:  use lower case names for libraries
add_subdirectory(src/amber_api)
add_subdirectory(src/amber_token_provider)
add_subdirectory(src/amber_token_verifier)
add_subdirectory(src/amber_sgx)
add_subdirectory(src/amber_tdx)
add_subdirectory(examples)
