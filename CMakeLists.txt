cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 17)
project(shadowsocks-asio)

#set(Boost_USE_STATIC_LIBS ON)
include(${PROJECT_SOURCE_DIR}/cmake/external/cryptopp.cmake)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

find_package(Boost 1.66 COMPONENTS system REQUIRED )

include_directories(${Boost_INCLUDE_DIR} ${CryptoPP_INCLUDE_DIRS} ${CryptoPP_INCLUDE_DIRS}/cryptopp)

find_package(Threads)

include_directories(./include)

file(GLOB_RECURSE HEADER_FILES "./include/*.h ./include/detail/*.h")
add_custom_target(headers SOURCES ${HEADER_FILES})

add_executable(ss-server 
	${HEADER_FILES}
	src/server.cpp
	)
add_dependencies(ss-server CryptoPP)


target_link_libraries(ss-server
	${Boost_LIBRARIES}
	${CryptoPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	)

