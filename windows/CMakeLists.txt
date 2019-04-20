# Only MSC comilers are supported */
cmake_minimum_required(VERSION 3.0.0)
project(VirtualLAN)

set(CMAKE_BUILD_TYPE release)

add_definitions("/D_WIN32_NT=0x0601 /D_CRT_SECURE_NO_WARNINGS /wd4005 /wd4996 /nologo")
add_definitions("-DWIN32_LEAN_AND_MEAN") 
add_definitions("-D_WIN32_NT=0x0601") 
add_definitions("-D_CRT_SECURE_NO_WARNINGS /wd4005 /wd4996 /nologo")

set(wxWidgets_ROOT_DIR "E:/wxWidgets-3.1.0")
set(wxWidgets_LIB_DIR "${wxWidgets_ROOT_DIR}/lib/vc_lib")
find_package(wxWidgets COMPONENTS core base adv)
if(NOT wxWidgets_FOUND)
	message(FATAL_ERROR "wxWidgets not found! Please set wxWidgets_ROOT_DIR variable in CMakeLists.txt.")
endif()
include(${wxWidgets_USE_FILE})

SET(BOOST_ROOT  "E:/boost_1_59_0")
find_package(Boost 1.59.0)
if(NOT Boost_FOUND)
	message(FATAL_ERROR "Cannot find boost! Please set BOOST_ROOT variable in CMakeLists.txt.")
endif()
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

# include_directories("../headers")
# build 'libmonkeyvpn' first
include_directories("../3rdparty")

set(HEADERS tap_device.hpp vl_packet.hpp)
add_executable(MonkeyVPN WIN32  "monkeyvpn.rc" "main.cpp" "tap_device.cpp" "../3rdparty/uECC.c" "../3rdparty/lzf_c.c" "../3rdparty/lzf_d.c")
target_link_libraries(MonkeyVPN  ${wxWidgets_LIBRARIES} ${Boost_LIBRARIES})
