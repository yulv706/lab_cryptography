cmake_minimum_required(VERSION 3.10)
project(CryptoService)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_definitions(-DCROW_USE_BOOST)

# 使用 Boost 的 asio
add_definitions(-DCROW_USE_BOOST_ASIO)

# 查找依赖
find_package(Boost REQUIRED COMPONENTS system)
find_package(TinyXML2 REQUIRED)

# Crypto++ 头文件和库
include_directories(/usr/include/cryptopp)
link_directories(/usr/lib)

# Crow 和 Boost 的头文件
include_directories(/usr/local/include /usr/include /usr/include/boost)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

# 创建共享库
add_library(CryptoCore SHARED CryptoCore.cpp)
target_link_libraries(CryptoCore PRIVATE cryptopp)

# 创建可执行文件
add_executable(CryptoService CryptoService.cpp)
target_link_libraries(CryptoService PRIVATE
    CryptoCore
    cryptopp
    tinyxml2::tinyxml2
    Boost::system
    pthread
)
