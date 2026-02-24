# Crypto unit tests

add_executable(test_kyber test_kyber.c)
target_link_libraries(test_kyber PRIVATE qshield-crypto)
target_include_directories(test_kyber PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME kyber COMMAND test_kyber)

add_executable(test_dilithium test_dilithium.c)
target_link_libraries(test_dilithium PRIVATE qshield-crypto)
target_include_directories(test_dilithium PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME dilithium COMMAND test_dilithium)

add_executable(test_hybrid test_hybrid.c)
target_link_libraries(test_hybrid PRIVATE qshield-crypto)
target_include_directories(test_hybrid PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME hybrid COMMAND test_hybrid)
