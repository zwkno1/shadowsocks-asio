cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(shadowsocks-asio)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

include(${PROJECT_SOURCE_DIR}/cmake/external/cryptopp.cmake)
include(${PROJECT_SOURCE_DIR}/cmake/external/spdlog.cmake)

find_package(Threads)

set(Boost_INCLUDE_DIR /usr/include/boost169)
set(BOOST_LIBRARYDIR /usr/lib64/boost169)
#option(Boost_USE_STATIC_LIBS "use boost static libs" ON)
find_package(Boost 1.69 COMPONENTS system program_options coroutine thread REQUIRED)
#message("-------${Boost_INCLUDE_DIR}-----")
#message("-------${Boost_LIBRARIES}-------")

set(GPERFTOOLS_USE_STATIC_LIBS TRUE)
find_package(gperftools REQUIRED)

include_directories(${Boost_INCLUDE_DIR} 
	${CRYPTOPP_INCLUDE_DIRS} 
	${GPERFTOOLS_INCLUDE_DIR}
	${SPDLOG_INCLUDE_DIRS}
	./third_party/serialization2/include
	./include 
	)

file(GLOB_RECURSE HEADER_FILES "./include/*.h ./include/detail/*.h")
add_custom_target(headers SOURCES ${HEADER_FILES})

# ss-local
#add_executable(ss-local
#	${HEADER_FILES}
#	src/main.cpp
#	)
#add_dependencies(ss-local CRYPTOPP SPDLOG)
#
#target_link_libraries(ss-local
#	${Boost_LIBRARIES}
#	${CRYPTOPP_LIBRARIES}
#	${CMAKE_THREAD_LIBS_INIT}
#	${GPERFTOOLS_TCMALLOC_LIBRARY}
#	)

#ss-server
add_executable(ss-server 
	${HEADER_FILES}
	src/main.cpp
	)
add_dependencies(ss-server CRYPTOPP SPDLOG)

set_target_properties(
    ss-server
    PROPERTIES
    COMPILE_DEFINITIONS BUILD_SHADOWSOCKS_SERVER=1
    )

target_link_libraries(ss-server
	${Boost_LIBRARIES}
	${CRYPTOPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${GPERFTOOLS_TCMALLOC_LIBRARY}
	)


add_definitions(
	-DBOOST_COROUTINES_NO_DEPRECATION_WARNING=1
	)
option(SHADOWSOCKS_ENABLE_TEST "build test" OFF)
if(SHADOWSOCKS_ENABLE_TEST STREQUAL "ON")
add_executable(cipher_test
	${HEADER_FILES}
	test/cipher_test.cpp
	)
add_dependencies(cipher_test CRYPTOPP)
target_link_libraries(cipher_test
	${CRYPTOPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	)
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/client.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/server.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/change_cipher.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

