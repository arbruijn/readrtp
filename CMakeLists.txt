cmake_minimum_required(VERSION 3.20)

project(readrtp VERSION 0.1.0 LANGUAGES CXX)

option(READRTP_BUILD_TESTS "Build the tests" ON)

set(READRTP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(readrtp STATIC
    src/error.cpp
    src/buffer.cpp
    src/types.cpp
    src/checksum.cpp
    src/patch_applier.cpp
    src/parse.cpp
    src/decompression.cpp
    src/apply.cpp
)

target_include_directories(readrtp
    PUBLIC
        "${READRTP_INCLUDE_DIR}"
)

target_compile_features(readrtp PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(readrtp PRIVATE /W4 /permissive-)
else()
    target_compile_options(readrtp PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(apply
    src/cli/apply_main.cpp
)
target_link_libraries(apply PRIVATE readrtp)

if(READRTP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
