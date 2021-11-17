cmake_minimum_required(VERSION 3.19)
project(spdlog_clion_test)

set(CMAKE_CXX_STANDARD 14)

# 输出编译信息
message("Hello spdlog!!! Start compile!")

#message(STATUS "yuhaoo PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")
# 设置源码根路径，即 cpp 目录
set(SRC_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
message(${SRC_ROOT_PATH})

# 定义要编译的文件列表变量
#file(GLOB CPP_FILES_IN_UTILS "${SRC_ROOT_PATH}/utils/*.cpp")
# 设置要编译的源文件
set(
        SOURCE_FILES
        #        ${CPP_FILES_IN_UTILS}
        ${SRC_ROOT_PATH}/main.cpp
)


message(${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include)
# include 头文件目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/openssl/utils/include)
add_subdirectory(openssl)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/zorro/encrypt)
add_subdirectory(zorro)

#FIND_PACKAGE(PkgConfig REQUIRED)
#PKG_SEARCH_MODULE(PKG_OPENSSL REQUIRED openssl)
#PKG_SEARCH_MODULE(PKG_LIBSSL REQUIRED libssl)
#PKG_SEARCH_MODULE(PKG_LIBCRYPTO REQUIRED libcrypto)
#INCLUDE_DIRECTORIES(${PKG_OPENSSL_INCLUDE_DIRS})

include_directories(${SRC_ROOT_PATH}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include)

add_subdirectory(spdlog)

# 编译成可执行文件，如果编译动态库可以用：target_link_libraries
add_executable(spdlog-decrypt ${SOURCE_FILES})

# 将第三方的库链接到可执行文件
target_link_libraries(spdlog-decrypt zorro-encrypt spdlog::spdlog  openssl-utils )
#target_link_libraries(spdlogDecrypt openssl-utils)

#add_executable(spdlogtest main.cpp)