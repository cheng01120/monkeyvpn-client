CMAKE_MINIMUM_REQUIRED(VERSION 3.5.1)

PROJECT(MonkeyVPN)
SET(CMAKE_BUILD_TYPE Release)

# boost
set(BOOST_ROOT "/root/git/boost_1_65_0")
find_package(Boost 1.65.0 REQUIRED COMPONENTS system )
if(NOT Boost_FOUND)
	message(fatal_error "Unable to find Boost!")
endif()
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR})

# cxx11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
	message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

SET(ARCH "x64")
include_directories("../headers")
# build 'libmonkeyvpn' first
link_directories("../lib")
add_executable(mvpn "main.cpp" "tun_alloc.cpp" "auth_sqlite3.cpp")
target_link_libraries(mvpn ${Boost_LIBRARIES} monkeyvpn-${ARCH} pthread sqlite3 crypt)
