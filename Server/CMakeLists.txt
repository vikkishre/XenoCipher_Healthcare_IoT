cmake_minimum_required(VERSION 3.15)
project(XenoCipherServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set vcpkg toolchain if not already set
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# Find packages using vcpkg
find_package(cpprestsdk CONFIG REQUIRED)
find_package(MbedTLS CONFIG REQUIRED)
find_package(libpqxx CONFIG REQUIRED)

# Define correct paths based on your structure
set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(LIB_ROOT "${PROJECT_ROOT}/../lib")  # F:\MajorProject1\lib
set(NTRU_ROOT "${LIB_ROOT}/NTRU")
set(ENTROPY_ROOT "${LIB_ROOT}/Entropy")

# Debug: Print paths
message(STATUS "Project root: ${PROJECT_ROOT}")
message(STATUS "Lib root: ${LIB_ROOT}")
message(STATUS "NTRU root: ${NTRU_ROOT}")
message(STATUS "Entropy root: ${ENTROPY_ROOT}")

# Source files - start with just main.cpp
set(SOURCES "${PROJECT_ROOT}/main.cpp")

# Check and add NTRU source if it exists
if(EXISTS "${NTRU_ROOT}/src/ntru.cpp" AND EXISTS "${NTRU_ROOT}/include")
    message(STATUS "Found NTRU source: ${NTRU_ROOT}/src/ntru.cpp")
    list(APPEND SOURCES "${NTRU_ROOT}/src/ntru.cpp")
else()
    message(WARNING "NTRU library not found or incomplete at: ${NTRU_ROOT}")
    message(WARNING "Expected: ${NTRU_ROOT}/src/ntru.cpp and ${NTRU_ROOT}/include/")
endif()

# Check and add Entropy source if it exists
if(EXISTS "${ENTROPY_ROOT}/src/entropy.cpp" AND EXISTS "${ENTROPY_ROOT}/include")
    message(STATUS "Found Entropy source: ${ENTROPY_ROOT}/src/entropy.cpp")
    list(APPEND SOURCES "${ENTROPY_ROOT}/src/entropy.cpp")
else()
    message(WARNING "Entropy library not found or incomplete at: ${ENTROPY_ROOT}")
    message(WARNING "Expected: ${ENTROPY_ROOT}/src/entropy.cpp and ${ENTROPY_ROOT}/include/")
endif()

# Verify main.cpp exists
if(NOT EXISTS "${PROJECT_ROOT}/main.cpp")
    message(FATAL_ERROR "main.cpp not found at: ${PROJECT_ROOT}/main.cpp")
    message(FATAL_ERROR "Please create main.cpp in the Server directory")
endif()

message(STATUS "Source files: ${SOURCES}")

# Create executable FIRST
add_executable(server ${SOURCES})

# Include directories - only add if directories exist
if(EXISTS "${NTRU_ROOT}/include")
    target_include_directories(server PRIVATE "${NTRU_ROOT}/include")
    message(STATUS "Added NTRU includes: ${NTRU_ROOT}/include")
endif()

if(EXISTS "${ENTROPY_ROOT}/include")
    target_include_directories(server PRIVATE "${ENTROPY_ROOT}/include")
    message(STATUS "Added Entropy includes: ${ENTROPY_ROOT}/include")
endif()

# Link libraries
target_link_libraries(server PRIVATE
    cpprestsdk::cpprest
    libpqxx::pqxx
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
)

# Compiler-specific options
if(MSVC)
    target_compile_options(server PRIVATE /W4)
    target_compile_definitions(server PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Set output directories
set_target_properties(server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Copy required DLLs for Windows
if(WIN32)
    # Find vcpkg bin directory
    get_filename_component(VCPKG_ROOT "${CMAKE_PREFIX_PATH}" REALPATH)
    if(NOT VCPKG_ROOT)
        set(VCPKG_ROOT "C:/Users/leela/vcpkg/installed/x64-windows")
    endif()
    set(VCPKG_BIN_DIR "${VCPKG_ROOT}/bin")
    
    message(STATUS "VCPKG bin dir: ${VCPKG_BIN_DIR}")
    
    # Copy PostgreSQL DLL
    if(EXISTS "${VCPKG_BIN_DIR}/libpq.dll")
        add_custom_command(TARGET server POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo "Copying libpq.dll..."
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VCPKG_BIN_DIR}/libpq.dll"
                $<TARGET_FILE_DIR:server>
        )
    endif()
    
    # Copy mbedTLS DLLs
    foreach(lib mbedcrypto mbedtls mbedx509)
        set(lib_dll "${VCPKG_BIN_DIR}/${lib}.dll")
        if(EXISTS "${lib_dll}")
            add_custom_command(TARGET server POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E echo "Copying ${lib}.dll..."
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${lib_dll}"
                    $<TARGET_FILE_DIR:server>
            )
        endif()
    endforeach()
