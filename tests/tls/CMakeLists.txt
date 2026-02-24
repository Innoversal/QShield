# TLS handshake tests

add_executable(test_tls_handshake test_tls_handshake.c)
target_link_libraries(test_tls_handshake PRIVATE qshield-tls qshield-crypto)
target_include_directories(test_tls_handshake PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME tls_handshake COMMAND test_tls_handshake)
