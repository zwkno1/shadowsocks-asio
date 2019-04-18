cmake_minimum_required(VERSION 2.8)

project(shadowsocks_test)

#set(Boost_USE_STATIC_LIBS ON)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake ${CMAKE_MODULE_PATH})

find_package(Boost 1.66 COMPONENTS system REQUIRED )
find_package(Botan2 2.9.0 REQUIRED)

include_directories(${Boost_INCLUDE_DIR} ${BOTAN2_INCLUDE_DIRS})

find_package(Threads)

include_directories(../include)

file(GLOB_RECURSE HEADER_FILES "../include/*.h ../include/detail/*.h")
add_custom_target(headers SOURCES ${HEADER_FILES})

add_executable(stream_test stream_test.cpp)
target_link_libraries(stream_test ${Boost_LIBRARIES}
	${BOTAN2_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	)
