# qshield-tls — Hybrid quantum-safe TLS 1.3 handshake

add_library(qshield-tls
    tls_ctx.c
    tls_handshake.c
)

target_include_directories(qshield-tls
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(qshield-tls
    PUBLIC  qshield-crypto
    PRIVATE OpenSSL::Crypto
)

set_target_properties(qshield-tls PROPERTIES
    OUTPUT_NAME qshield_tls
    VERSION     ${PROJECT_VERSION}
    SOVERSION   ${PROJECT_VERSION_MAJOR}
)
