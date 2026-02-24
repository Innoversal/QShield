# QShield CLI tools

add_executable(qshield-keygen keygen.c)
target_link_libraries(qshield-keygen PRIVATE qshield-crypto)
