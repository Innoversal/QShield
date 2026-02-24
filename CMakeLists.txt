cmake_minimum_required(VERSION 3.16)

# QShield — Quantum-Safe Security Infrastructure for the Internet
# Created by Abu Bokor Siddick, Innoversal (Bangladesh)

project(QShield
    VERSION 0.1.0
    DESCRIPTION "Quantum-Safe Security Infrastructure for the Internet"
    HOMEPAGE_URL "https://github.com/Innoversal/QShield"
    LANGUAGES C
)

# --------------------------------------------------------------------
# Build options
# --------------------------------------------------------------------
option(QSHIELD_BUILD_TESTS    "Build unit tests"              ON)
option(QSHIELD_BUILD_TOOLS    "Build CLI tools"               ON)
option(QSHIELD_USE_SYSTEM_OQS "Use system-installed liboqs"   OFF)

# --------------------------------------------------------------------
# Compiler settings
# --------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Strict warnings — crypto code must compile cleanly
add_compile_options(
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wconversion -Wstrict-prototypes
    -fstack-protector-strong
)

# Position-independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export compile commands for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------
include(cmake/FindOQS.cmake)

find_package(OpenSSL 3.0 REQUIRED)

# --------------------------------------------------------------------
# Libraries
# --------------------------------------------------------------------
add_subdirectory(src/crypto)
add_subdirectory(src/tls)

# --------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------
if(QSHIELD_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------
if(QSHIELD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
