cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME localproxy)
set(AWS_TUNNEL_LOCAL_PROXY_LIB_NAME lproxy)
project(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} CXX)

option(BUILD_TESTS "Build tests" OFF)
option(LINK_STATIC_OPENSSL "Use static openssl libs" ON)
option(GIT_VERSION "Updates the version number using the Git commit history" ON)
if(BUILD_TESTS)
    set(AWS_TUNNEL_LOCAL_PROXY_TEST_NAME localproxytest)
    project(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} CXX)
endif(BUILD_TESTS)

#########################################
# Generate Version Information from Git #
#########################################
find_package(Git)
include(CMakeLists.txt.versioning)
# Now we inject the version information into a header that is accessible from the local proxy executable
configure_file("src/Version.h.in" "${PROJECT_BINARY_DIR}/Version.h")

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
    set(CUSTOM_COMPILER_FLAGS "-O2 -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong -Wall -Werror")
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
set(PROTOBUF_PKG_VERSION "3.17.3" CACHE STRING "")
find_package(Protobuf ${PROTOBUF_PKG_VERSION} REQUIRED)
string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} Protobuf_LITE_STATIC_LIBRARY ${Protobuf_LITE_LIBRARY})
include_directories(SYSTEM ${Protobuf_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_BINARY_DIR}) #needed to include generated protobuf headers
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROJECT_SOURCE_DIR}/resources/Message.proto)

#########################################
# OpenSSL dependency                    #
#########################################
if(LINK_STATIC_OPENSSL)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()
find_package(OpenSSL REQUIRED)

if(LINK_STATIC_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
    
    # Check SSL library location
    get_target_property(SSL_LOCATION OpenSSL::SSL IMPORTED_LOCATION)
    if(SSL_LOCATION STREQUAL "SSL_LOCATION-NOTFOUND")
        get_target_property(SSL_LOCATION OpenSSL::SSL IMPORTED_LOCATION_RELEASE)
        if(SSL_LOCATION STREQUAL "SSL_LOCATION-NOTFOUND")
            message(FATAL_ERROR "Could not find OpenSSL SSL library location")
        endif()
    endif()
    
    # Check Crypto library location
    get_target_property(CRYPTO_LOCATION OpenSSL::Crypto IMPORTED_LOCATION)
    if(CRYPTO_LOCATION STREQUAL "CRYPTO_LOCATION-NOTFOUND")
        get_target_property(CRYPTO_LOCATION OpenSSL::Crypto IMPORTED_LOCATION_RELEASE)
        if(CRYPTO_LOCATION STREQUAL "CRYPTO_LOCATION-NOTFOUND")
            message(FATAL_ERROR "Could not find OpenSSL Crypto library location")
        endif()
    endif()
    
    string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} OpenSSL_STATIC_SSL_LIBRARY ${SSL_LOCATION})
    string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} OpenSSL_STATIC_CRYPTO_LIBRARY ${CRYPTO_LOCATION})
endif()

#########################################
# Test framework dependency             #
#########################################
#probably comment out for cross compiler as Catch2 is really just a header library
if(BUILD_TESTS)
    find_package(Catch2 3 REQUIRED)
endif(BUILD_TESTS)

#########################################
# Boost dependencies                    #
#########################################
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_DEBUG_RUNTIME OFF)
#set_property(GLOBAL PROPERTY Boost_USE_MULTITHREADED ON)
set(BOOST_PKG_VERSION "1.87.0" CACHE STRING "")
find_package(Boost ${BOOST_PKG_VERSION} REQUIRED COMPONENTS system log log_setup thread program_options date_time filesystem chrono)
include_directories(${Boost_INCLUDE_DIRS})
foreach(BOOST_LIB ${Boost_LIBRARIES})
    string(REPLACE ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX} BOOST_STATIC_LIB ${BOOST_LIB})
    list(APPEND Boost_STATIC_LIBRARIES ${BOOST_STATIC_LIB})
endforeach()

#########################################
# Target : Build aws-tunnel-local-proxy #
#########################################
file(GLOB ALL_SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)

set(UTIL_SOURCE ${PROJECT_SOURCE_DIR}/src/config/ConfigFile.cpp ${PROJECT_SOURCE_DIR}/src/Url.cpp)
set(CORE_SOURCES ${PROJECT_SOURCE_DIR}/src/TcpAdapterProxy.cpp ${PROJECT_SOURCE_DIR}/src/ProxySettings.cpp ${PROJECT_SOURCE_DIR}/src/WebProxyAdapter.cpp ${PROTO_HDRS} ${PROTO_SRCS} ${PROJECT_SOURCE_DIR}/src/WebSocketStream.cpp)
set(MAIN_SOURCES ${PROJECT_SOURCE_DIR}/src/main.cpp ${CORE_SOURCES} ${UTIL_SOURCE})
add_executable(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${MAIN_SOURCES})

if(BUILD_TESTS)
    file(GLOB TEST_CODE ${PROJECT_SOURCE_DIR}/test/*.cpp)
    set(TEST_SOURCES ${TEST_CODE} ${CORE_SOURCES} ${UTIL_SOURCE})
    add_executable(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${TEST_SOURCES})
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} Catch2::Catch2WithMain)
endif(BUILD_TESTS)

#libatomic ensured for all platforms except OSX and WINDOWS
if(NOT APPLE AND NOT MSVC AND NOT BUILD_TESTS)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} atomic)
elseif(NOT APPLE AND NOT MSVC AND BUILD_TESTS)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} atomic)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} atomic)
endif()

include_directories(${PROJECT_SOURCE_DIR}/src)

target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})
if(LINK_STATIC_OPENSSL)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${OpenSSL_STATIC_SSL_LIBRARY})
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${OpenSSL_STATIC_CRYPTO_LIBRARY})
else()
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} OpenSSL::SSL)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} OpenSSL::Crypto)
endif()
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${Boost_STATIC_LIBRARIES})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${Protobuf_LITE_STATIC_LIBRARY})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${CMAKE_DL_LIBS})
set_property(TARGET ${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} APPEND_STRING PROPERTY COMPILE_FLAGS ${CUSTOM_COMPILER_FLAGS})

if(BUILD_TESTS)
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${CMAKE_THREAD_LIBS_INIT})
    if(LINK_STATIC_OPENSSL)
        target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${OpenSSL_STATIC_SSL_LIBRARY})
        target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${OpenSSL_STATIC_CRYPTO_LIBRARY})
    else()
        target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} OpenSSL::SSL)
        target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} OpenSSL::Crypto)
    endif()
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${Boost_STATIC_LIBRARIES})
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${Protobuf_LITE_STATIC_LIBRARY})
    target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${CMAKE_DL_LIBS})
    set_property(TARGET ${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} APPEND_STRING PROPERTY COMPILE_FLAGS ${TEST_COMPILER_FLAGS})
endif(BUILD_TESTS)

install(TARGETS ${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} DESTINATION "bin")
