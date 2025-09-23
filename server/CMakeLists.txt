cmake_minimum_required(VERSION 3.15)
project(XenoCipherServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define Windows target version for ASIO
add_definitions(-D_WIN32_WINNT=0x0601) # Windows 7 or later

# Find packages
find_package(Crow REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(libpqxx CONFIG REQUIRED)
find_package(PostgreSQL REQUIRED)

# XenoCipher lib includes (relative to server/ directory)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/NTRU/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/CryptoKDF/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/HMAC/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LFSR/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/Tinkerbell/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/Transposition/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/common
    ${MbedTLS_INCLUDE_DIRS}
)

# libpqxx is provided by vcpkg; no manual include/lib paths needed

# Source files
add_executable(server
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/NTRU/src/ntru.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/CryptoKDF/src/crypto_kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/HMAC/src/hmac.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LFSR/src/lfsr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/Tinkerbell/src/tinkerbell.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/Transposition/src/transposition.cpp
)

# Link libraries
target_link_libraries(server PRIVATE
    Crow::Crow
    libpqxx::pqxx
    PostgreSQL::PostgreSQL
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
)