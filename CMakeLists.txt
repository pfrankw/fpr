cmake_minimum_required(VERSION 2.8)

project("fpr" C)
SET(FPR_VERSION "0.1.0")

SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/bin")
SET(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib")

SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall")
SET(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG}")
SET(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE}")

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RELEASE")
endif()

message("Current CMake build type is ${CMAKE_BUILD_TYPE}")

option(CRYPTO "Enable mbedtls encryption" OFF)

include_directories("include" "${CMAKE_SOURCE_DIR}/ext/mbedtls/include")
include_directories("${CMAKE_SOURCE_DIR}/ext/uthash/include")

link_directories("${CMAKE_SOURCE_DIR}/ext/mbedtls/library")

add_subdirectory(src)
add_subdirectory(programs)
