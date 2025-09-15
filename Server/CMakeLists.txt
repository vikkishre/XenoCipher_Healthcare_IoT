cmake_minimum_required(VERSION 3.15)
project(XenoCipherServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(cpprestsdk REQUIRED)
find_package(MbedTLS REQUIRED)

# NTRU and Entropy includes
include_directories(../../lib/NTRU/include ../../lib/Entropy/include ${MbedTLS_INCLUDE_DIRS})

# libpqxx manual paths
set(PQXX_INCLUDE "C:/Users/leela/vcpkg/installed/x64-windows/include")
set(PQXX_LIB "C:/Users/leela/vcpkg/installed/x64-windows/lib/pqxx.lib")
set(PQ_LIB "C:/Users/leela/vcpkg/installed/x64-windows/lib/libpq.lib")

include_directories(${PQXX_INCLUDE})

# Source files
add_executable(server main.cpp ../../lib/NTRU/src/ntru.cpp ../../lib/Entropy/src/entropy.cpp)

# Link libraries
target_link_libraries(server PRIVATE
    cpprestsdk::cpprest
    ${PQXX_LIB}
    ${PQ_LIB}
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
)