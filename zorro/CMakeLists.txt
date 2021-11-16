cmake_minimum_required(VERSION 3.16)
project(zorro-encrypt)
set(CMAKE_CXX_STANDARD 14)

find_library(SSL_LIB ssl)
find_library(CRYPTO_LIB crypto)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/encrypt)
set(
        ZORRO_ENCRYPT_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/encrypt/xor.cc)

message(STATUS "zorro-encrypt SRC_ROOT_PATH: " ${SRC_ROOT_PATH})
message(STATUS "zorro-encrypt CMAKE_CURRENT_SOURCE_DIR: " ${CMAKE_CURRENT_SOURCE_DIR})

# message("ossl utils PKG_OPENSSL_LDFLAGS " ${PKG_OPENSSL_LDFLAGS})
add_library(zorro-encrypt STATIC ${ZORRO_ENCRYPT_FILES})

#target_link_libraries(openssl-utils ${SSL_LIB} ${CRYPTO_LIB})