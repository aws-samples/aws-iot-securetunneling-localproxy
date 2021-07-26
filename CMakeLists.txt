cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

set(AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME localproxy)
set(AWS_TUNNEL_LOCAL_PROXY_LIB_NAME lproxy)
set(AWS_TUNNEL_LOCAL_PROXY_TEST_NAME localproxytest)

project(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} CXX)
project(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} CXX)

######################################
# Section : Disable in-source builds #
######################################

if (${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR})
    message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt and CMakeFiles folder.")
endif ()

########################################
# Section : Common Build setttings #
########################################
# Set required compiler standard to standard c++11. Disable extensions.
set(CMAKE_CXX_STANDARD 14) # C++14
set(CMAKE_CXX_STANDARD_REQUIRED ON) #...is required...
set(CMAKE_CXX_EXTENSIONS OFF) #...without compiler extensions like gnu++11

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Configure Compiler flags
if (UNIX OR APPLE)
    set(CUSTOM_COMPILER_FLAGS "-O2 -D_FORTIFY_SOURCE=2 -fPIE -Wall -Werror")
    set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} -D_AWSIOT_TUNNELING_NO_SSL")
elseif (WIN32 OR MSVC)
    set(CUSTOM_COMPILER_FLAGS "/W4 /DYNAMICBASE /NXCOMPAT /analyze")
    set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} /D_AWSIOT_TUNNELING_NO_SSL")
    add_definitions(-D_WIN32_WINNT=${WIN32_WINNT})
endif ()


#########################################
# Threading library needed for GCC      #
#########################################
find_package(Threads)

#########################################
# Generate protobuf files               #
#########################################
set_property(GLOBAL PROPERTY PROTOBUF_USE_STATIC_LIBS ON)  #this flag doesn't actually seem to work yet but it's documented
find_package(Protobuf 3.17.3 REQUIRED)
string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} Protobuf_LITE_STATIC_LIBRARY ${Protobuf_LITE_LIBRARY})
include_directories(${Protobuf_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_BINARY_DIR}) #needed to include generated protobuf headers
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROJECT_SOURCE_DIR}/resources/Message.proto)

#########################################
# OpenSSL dependency                    #
#########################################
find_package(OpenSSL REQUIRED)

#########################################
# Test framework dependency             #
#########################################
#probably comment out for cross compiler as Catch2 is really just a header library
find_package(Catch2 REQUIRED)

#########################################
# Boost dependencies                    #
#########################################
set_property(GLOBAL PROPERTY Boost_USE_STATIC_LIBS ON)
set_property(GLOBAL PROPERTY Boost_USE_DEBUG_RUNTIME OFF)
#set_property(GLOBAL PROPERTY Boost_USE_MULTITHREADED ON)
find_package(Boost 1.76.0 REQUIRED COMPONENTS system log log_setup thread program_options date_time filesystem)
include_directories(${Boost_INCLUDE_DIRS})
foreach(BOOST_LIB ${Boost_LIBRARIES})
    string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} BOOST_STATIC_LIB ${BOOST_LIB})
    list(APPEND Boost_STATIC_LIBRARIES ${BOOST_STATIC_LIB})
endforeach()

#########################################
# Target : Build aws-tunnel-local-proxy #
#########################################
file(GLOB ALL_SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)
file(GLOB TEST_CODE ${PROJECT_SOURCE_DIR}/test/*.cpp)

set(UTIL_SOURCE ${PROJECT_SOURCE_DIR}/src/config/ConfigFile.cpp ${PROJECT_SOURCE_DIR}/src/Url.cpp)
set(CORE_SOURCES ${PROJECT_SOURCE_DIR}/src/TcpAdapterProxy.cpp ${PROJECT_SOURCE_DIR}/src/ProxySettings.cpp ${PROJECT_SOURCE_DIR}/src/WebProxyAdapter.cpp ${PROTO_HDRS} ${PROTO_SRCS} ${PROJECT_SOURCE_DIR}/src/WebSocketStream.cpp)
set(MAIN_SOURCES ${PROJECT_SOURCE_DIR}/src/main.cpp ${CORE_SOURCES} ${UTIL_SOURCE})
set(TEST_SOURCES ${TEST_CODE} ${CORE_SOURCES} ${UTIL_SOURCE})

add_executable(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${MAIN_SOURCES})
add_executable(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${TEST_SOURCES})

#libatomic ensured for all platforms except OSX and WINDOWS
if(NOT APPLE AND NOT MSVC)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} atomic)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} atomic)
endif()

target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} OpenSSL::SSL)
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} OpenSSL::Crypto)
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${Boost_STATIC_LIBRARIES})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${Protobuf_LITE_STATIC_LIBRARY})


include_directories(${PROJECT_SOURCE_DIR}/src)
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} OpenSSL::SSL)
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} OpenSSL::Crypto)
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${Boost_STATIC_LIBRARIES})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${Protobuf_LITE_STATIC_LIBRARY})


set_property(TARGET ${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} APPEND_STRING PROPERTY COMPILE_FLAGS ${CUSTOM_COMPILER_FLAGS})
set_property(TARGET ${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} APPEND_STRING PROPERTY COMPILE_FLAGS ${TEST_COMPILER_FLAGS})
