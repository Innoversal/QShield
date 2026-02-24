# qshield-crypto — PQC primitive wrappers (Kyber + Dilithium)

add_library(qshield-crypto
    qshield_init.c
    kyber.c
    dilithium.c
    hybrid.c
    secure_mem.c
)

target_include_directories(qshield-crypto
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(qshield-crypto
    PUBLIC  OQS::oqs
    PRIVATE OpenSSL::Crypto
)

set_target_properties(qshield-crypto PROPERTIES
    OUTPUT_NAME qshield_crypto
    VERSION     ${PROJECT_VERSION}
    SOVERSION   ${PROJECT_VERSION_MAJOR}
)
