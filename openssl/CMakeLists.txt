cmake_minimum_required(VERSION 3.16)
project(openssl-utils)
set(CMAKE_CXX_STANDARD 14)
if (WIN32 OR MSVC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
elseif (UNIX)
    # 仅查找静态库，强制后缀为 .a
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    # 如果只是优先查找静态库，保证 .a 后缀在前面即可，把默认的后缀加上
    # set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif()

find_library(SSL_LIB ssl)
find_library(CRYPTO_LIB crypto)

FIND_PACKAGE(PkgConfig REQUIRED)
PKG_SEARCH_MODULE(PKG_OPENSSL REQUIRED openssl)
# PKG_SEARCH_MODULE(PKG_LIBSSL REQUIRED libssl)
# PKG_SEARCH_MODULE(PKG_LIBCRYPTO REQUIRED libcrypto)
#set(OPENSSL_USE_STATIC_LIBS TRUE)

#INCLUDE_DIRECTORIES(${PKG_OPENSSL_INCLUDE_DIRS})
include_directories(${PKG_OPENSSL_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/openssl/utils/include)
set(
        OPENSSL_UTILS_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/src/AES.cpp ${CMAKE_CURRENT_SOURCE_DIR}/utils/src/Padding.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/src/AES2.cpp ${CMAKE_CURRENT_SOURCE_DIR}/utils/src/Padding2.cpp
        utils/src/spd_aes.cpp utils/include/spd_aes.h)

#file(GLOB OPENSSL_UTILS_FILES "${CMAKE_CURRENT_SOURCE_DIR}/utils/src/*.cpp")
message(STATUS "ossl PKG_OPENSSL_INCLUDE_DIRS path " ${PKG_OPENSSL_INCLUDE_DIRS})
message(STATUS "ossl utils path " ${SRC_ROOT_PATH})
message(STATUS "ossl utils path " ${CMAKE_CURRENT_SOURCE_DIR}/src/AES.cpp)

# message("ossl utils PKG_OPENSSL_LDFLAGS " ${PKG_OPENSSL_LDFLAGS})
add_library(openssl-utils STATIC ${OPENSSL_UTILS_FILES})

target_link_libraries(openssl-utils ${SSL_LIB} ${CRYPTO_LIB})