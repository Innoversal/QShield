# FindOQS.cmake
# Locate liboqs (Open Quantum Safe) library
#
# If QSHIELD_USE_SYSTEM_OQS is ON, look for a system installation.
# Otherwise, fetch and build liboqs via FetchContent.

if(QSHIELD_USE_SYSTEM_OQS)
    find_library(OQS_LIBRARY NAMES oqs)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)

    if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
        message(STATUS "Found system liboqs: ${OQS_LIBRARY}")
        add_library(OQS::oqs UNKNOWN IMPORTED)
        set_target_properties(OQS::oqs PROPERTIES
            IMPORTED_LOCATION "${OQS_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OQS_INCLUDE_DIR}"
        )
    else()
        message(FATAL_ERROR
            "QSHIELD_USE_SYSTEM_OQS is ON but liboqs was not found. "
            "Install liboqs or set QSHIELD_USE_SYSTEM_OQS=OFF to auto-fetch."
        )
    endif()
else()
    include(FetchContent)
    FetchContent_Declare(
        liboqs
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG        0.12.0
        GIT_SHALLOW    TRUE
    )

    # Configure liboqs build — only enable algorithms we need
    set(OQS_ENABLE_KEM_KYBER ON CACHE BOOL "" FORCE)
    set(OQS_ENABLE_SIG_DILITHIUM ON CACHE BOOL "" FORCE)
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD "KEM_kyber_768;SIG_dilithium_3" CACHE STRING "" FORCE)

    # Suppress liboqs warnings during our build
    set(CMAKE_C_FLAGS_SAVED "${CMAKE_C_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")

    FetchContent_MakeAvailable(liboqs)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_SAVED}")

    add_library(OQS::oqs ALIAS oqs)
endif()
