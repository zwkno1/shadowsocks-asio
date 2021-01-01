cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(shadowsocks-asio)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

include(${PROJECT_SOURCE_DIR}/cmake/external/cryptopp.cmake)
include(${PROJECT_SOURCE_DIR}/cmake/external/spdlog.cmake)

find_package(Threads)

add_definitions(
	-DBOOST_COROUTINES_NO_DEPRECATION_WARNING=1
)
option(Boost_USE_STATIC_LIBS "use boost static libs" ON)
find_package(Boost 1.70 COMPONENTS system program_options coroutine thread unit_test_framework REQUIRED)


include_directories(${Boost_INCLUDE_DIR} 
	${CRYPTOPP_INCLUDE_DIRS} 
	${SPDLOG_INCLUDE_DIRS}
	./third_party/serialization2/include
	./include 
)

# ss-local
add_executable(ss-local
	src/main.cpp
)
add_dependencies(ss-local CRYPTOPP SPDLOG)

target_link_libraries(ss-local
	${Boost_LIBRARIES}
	${CRYPTOPP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
)

# ss-server
add_executable(ss-server 
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
)

option(ENABLE_TEST "build test" OFF)
if(ENABLE_TEST STREQUAL "ON")
    include(CTest)
    enable_testing()
    
    add_executable(cipher_test test/cipher_test.cpp)
    add_dependencies(cipher_test CRYPTOPP SPDLOG)
    target_link_libraries(cipher_test
    	${CRYPTOPP_LIBRARIES}
    	${Boost_LIBRARIES}
    	${CMAKE_THREAD_LIBS_INIT}
	)
		
    add_test(NAME cipher_test COMMAND cipher_test)
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/client.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/server.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/change_cipher.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

