cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_STANDARD 17)

project(shadowsocks-asio)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

include(${PROJECT_SOURCE_DIR}/cmake/external/cryptopp.cmake)

find_package(Threads)

option(Boost_USE_STATIC_LIBS "use boost static libs" ON)
find_package(Boost 1.66 COMPONENTS system program_options REQUIRED)

set(GPERFTOOLS_USE_STATIC_LIBS TRUE)
find_package(gperftools REQUIRED)

include_directories(${Boost_INCLUDE_DIR} 
	${CryptoPP_INCLUDE_DIRS} 
	${CryptoPP_INCLUDE_DIRS}/cryptopp
	${GPERFTOOLS_INCLUDE_DIR}
	./third_party/spdlog/include 
	./third_party/serialization2/include
	./include 
	)

file(GLOB_RECURSE HEADER_FILES "./include/*.h ./include/detail/*.h")
add_custom_target(headers SOURCES ${HEADER_FILES})

# ss-local
add_executable(ss-local
	${HEADER_FILES}
	src/server.cpp
	)
add_dependencies(ss-local CryptoPP)

target_link_libraries(ss-local
	${Boost_LIBRARIES}
	${CryptoPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${GPERFTOOLS_TCMALLOC_LIBRARY}
	)
	
#ss-server
add_executable(ss-server 
	${HEADER_FILES}
	src/server.cpp
	)
add_dependencies(ss-server CryptoPP)

set_target_properties(
    ss-server
    PROPERTIES
    COMPILE_DEFINITIONS BUILD_SHADOWSOCKS_SERVER=1
    )

target_link_libraries(ss-server
	${Boost_LIBRARIES}
	${CryptoPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${GPERFTOOLS_TCMALLOC_LIBRARY}
	)


option(SHADOWSOCKS_ENABLE_TEST "build test" OFF)
if(SHADOWSOCKS_ENABLE_TEST STREQUAL "ON")
add_executable(cipher_test
	${HEADER_FILES}
	test/cipher_test.cpp
	)
add_dependencies(cipher_test CryptoPP)
target_link_libraries(cipher_test
	${CryptoPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	)
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/client.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/server.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/change_cipher.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

