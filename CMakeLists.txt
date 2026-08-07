cmake_minimum_required(VERSION 3.10...3.30)

set(AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME localproxy)
# Unused; retained because it is part of the historical variable surface.
set(AWS_TUNNEL_LOCAL_PROXY_LIB_NAME lproxy)
project(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} CXX)

# ##############################################################################
# Section : Options #
# ##############################################################################

option(BUILD_TESTS "Build tests" OFF)
option(LINK_STATIC_OPENSSL "Use static openssl libs" ON)
option(LOCALPROXY_RELEASE "Build as release version without git hash" OFF)
option(DISABLE_SSL_HOST_VERIFY_OPT
       "Disable the --no-ssl-host-verify option for production builds" OFF)

# How dependencies declared in fc_deps.json are provided. `auto` probes for a
# pre-installed copy first and only builds from source when it is missing, so
# machines with the dependencies installed behave exactly as before.
set(LOCALPROXY_DEP_MODE
    "auto"
    CACHE STRING "Dependency resolution: auto, system or fetch")
set_property(CACHE LOCALPROXY_DEP_MODE PROPERTY STRINGS auto system fetch)

# Per-dependency overrides of LOCALPROXY_DEP_MODE; empty means "inherit".
set(LOCALPROXY_BOOST_SOURCE
    ""
    CACHE STRING "Override dependency mode for Boost")
set(LOCALPROXY_PROTOBUF_SOURCE
    ""
    CACHE STRING "Override dependency mode for Protobuf")
set(LOCALPROXY_CATCH2_SOURCE
    ""
    CACHE STRING "Override dependency mode for Catch2")

set(LOCALPROXY_LINK_ATOMIC
    "auto"
    CACHE STRING "Link libatomic: auto (probe), ON or OFF")
set_property(CACHE LOCALPROXY_LINK_ATOMIC PROPERTY STRINGS auto ON OFF)

set(LOCALPROXY_PROTOC_EXECUTABLE
    ""
    CACHE FILEPATH "Host protoc to use for codegen when cross-compiling")

# Windows API level. Must match the value Boost was built with, otherwise the
# Boost.Asio/Beast ABI does not line up.
set(WIN32_WINNT
    "0x0A00"
    CACHE STRING "Value of _WIN32_WINNT to compile against (Windows only)")

if(BUILD_TESTS AND NOT DEFINED BUILD_TESTING)
  set(BUILD_TESTING ON)
endif()

if(BUILD_TESTS)
  set(AWS_TUNNEL_LOCAL_PROXY_TEST_NAME localproxytest)
  # NOTE: this re-project() call changes PROJECT_NAME to localproxytest for the
  # rest of the file, and src/Version.h.in double-indirects through
  # ${${PROJECT_NAME}_VERSION_STRING_FULL}. The versioning module below runs
  # after it, so both agree -- do not reorder these.
  project(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} CXX)
endif(BUILD_TESTS)

# ##############################################################################
# Section : Disable in-source builds #
# ##############################################################################
# Checked before the versioning module runs, so that a rejected in-source build
# has no side effects.

if(${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR})
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt and CMakeFiles folder."
  )
endif()

# ##############################################################################
# Generate Version Information #
# ##############################################################################
file(READ version LP_VERSION)
string(STRIP "${LP_VERSION}" LP_VERSION)

find_package(Git)

if(NOT LOCALPROXY_RELEASE)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} -c safe.directory=${CMAKE_SOURCE_DIR} rev-parse
            --short=7 HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()

set(${PROJECT_NAME}_VERSION_STRING "v${LP_VERSION}")
if(GIT_COMMIT)
  set(${PROJECT_NAME}_VERSION_STRING_FULL "v${LP_VERSION}+${GIT_COMMIT}")
else()
  set(${PROJECT_NAME}_VERSION_STRING_FULL "v${LP_VERSION}")
endif()

message(
  "-- AWS IoT Secure Tunneling Local Proxy version: ${${PROJECT_NAME}_VERSION_STRING_FULL}"
)

# Now we inject the version information into a header that is accessible from
# the local proxy executable
configure_file("src/Version.h.in" "${PROJECT_BINARY_DIR}/Version.h")

# ##############################################################################
# Section : Common Build setttings #
# ##############################################################################
# Set required compiler standard to standard c++14. Disable extensions.
set(CMAKE_CXX_STANDARD 14) # C++14
set(CMAKE_CXX_STANDARD_REQUIRED ON) # ...is required...
set(CMAKE_CXX_EXTENSIONS OFF) # ...without compiler extensions like gnu++14

# Kept as a literal `bin`: Dockerfiles, CI artifact paths and the uat/ harness
# all hard-code <build-dir>/bin/localproxy.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Makes the shipped .clang-tidy usable, and keeps clangd working.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)
# NOTE: do NOT unset CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES here. That list is
# what stops `include_directories(SYSTEM ...)` from emitting `-isystem` for a
# directory the compiler already searches implicitly. Distro-packaged Boost and
# Protobuf live in /usr/include, so unsetting it yields `-isystem /usr/include`,
# which reorders the search path ahead of libstdc++'s own directories and breaks
# `#include_next` ("fatal error: stdlib.h: No such file or directory") in every
# translation unit.

# Reproducible builds; set before any dependency sub-build so it inherits them.
set(ENV{SOURCE_DATE_EPOCH} "0")
set(ENV{ZERO_AR_DATE} "1")

# Configure Compiler flags
if(UNIX OR APPLE)
  set(CUSTOM_COMPILER_FLAGS
      "-O2 -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong -Wall -Werror")
  set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} -D_AWSIOT_TUNNELING_NO_SSL")
  if(DISABLE_SSL_HOST_VERIFY_OPT)
    set(CUSTOM_COMPILER_FLAGS
        "${CUSTOM_COMPILER_FLAGS} -D_AWSIOT_TUNNELING_DISABLE_NO_SSL_HOST_VERIFY"
    )
  endif()
elseif(WIN32 OR MSVC)
  set(CUSTOM_COMPILER_FLAGS "/W4 /DYNAMICBASE /NXCOMPAT /analyze")
  set(TEST_COMPILER_FLAGS "${CUSTOM_COMPILER_FLAGS} /D_AWSIOT_TUNNELING_NO_SSL")
  if(DISABLE_SSL_HOST_VERIFY_OPT)
    set(CUSTOM_COMPILER_FLAGS
        "${CUSTOM_COMPILER_FLAGS} /D_AWSIOT_TUNNELING_DISABLE_NO_SSL_HOST_VERIFY"
    )
  endif()
  if(NOT WIN32_WINNT MATCHES "^0[xX][0-9A-Fa-f]+$")
    message(FATAL_ERROR "WIN32_WINNT must be a hexadecimal Windows API version"
                        " such as 0x0A00, got '${WIN32_WINNT}'.")
  endif()
  add_definitions(-D_WIN32_WINNT=${WIN32_WINNT})
endif()

# ##############################################################################
# Threading library needed for GCC      #
# ##############################################################################
find_package(Threads)

# ##############################################################################
# Section : Dependencies #
# ##############################################################################
# fc_deps.json is the single source of truth for the pinned version, URL and
# SHA256 of Boost, Protobuf and Catch2. OpenSSL and zlib intentionally stay
# system-provided; see cmake/LocalproxyOpenSSL.cmake.

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(LocalproxyUtil)
include(LocalproxyDeps)

localproxy_load_manifest()
localproxy_seed_version_cache()

# Cross-compilation relies on find_package resolving everything out of the
# sysroot (CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY), so do not fetch by default.
if(CMAKE_CROSSCOMPILING AND LOCALPROXY_DEP_MODE STREQUAL "auto")
  set(LOCALPROXY_DEP_MODE "system")
  message(
    STATUS "localproxy: cross-compiling, defaulting dependencies to system mode"
  )
endif()

include(LocalproxyProtobuf)
include(LocalproxyOpenSSL)
include(LocalproxyCatch2)
include(LocalproxyBoost)

# ##############################################################################
# Generate protobuf files               #
# ##############################################################################
# needed to include generated protobuf headers
include_directories(${CMAKE_CURRENT_BINARY_DIR})
lp_protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS
                         ${PROJECT_SOURCE_DIR}/resources/Message.proto)

# ##############################################################################
# Target : Build aws-tunnel-local-proxy #
# ##############################################################################
include_directories(${PROJECT_SOURCE_DIR}/src)

set(UTIL_SOURCE
    ${PROJECT_SOURCE_DIR}/src/config/ConfigFile.cpp
    ${PROJECT_SOURCE_DIR}/src/Url.cpp
    ${PROJECT_SOURCE_DIR}/src/InputValidation.cpp)
set(CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/TcpAdapterProxy.cpp
    ${PROJECT_SOURCE_DIR}/src/ProxySettings.cpp
    ${PROJECT_SOURCE_DIR}/src/WebProxyAdapter.cpp
    ${PROTO_HDRS}
    ${PROTO_SRCS}
    ${PROJECT_SOURCE_DIR}/src/WebSocketStream.cpp)
set(MAIN_SOURCES ${PROJECT_SOURCE_DIR}/src/main.cpp ${CORE_SOURCES}
                 ${UTIL_SOURCE})
add_executable(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${MAIN_SOURCES})

# CORE_SOURCES and UTIL_SOURCE are deliberately compiled a second time for the
# test binary rather than shared through an object/static library: the test
# build defines _AWSIOT_TUNNELING_NO_SSL, which swaps the websocket stream from
# TLS to plain TCP. Sharing compiled objects between the two targets would
# silently strip TLS from the production binary.
if(BUILD_TESTS)
  file(GLOB TEST_CODE CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/test/*.cpp)
  set(TEST_SOURCES ${TEST_CODE} ${CORE_SOURCES} ${UTIL_SOURCE})
  add_executable(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${TEST_SOURCES})
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        ${LOCALPROXY_CATCH2_LINK})
  # The shared sources appear in both targets with different flags; keep only
  # the production entries in compile_commands.json so tooling picks the right
  # one.
  set_target_properties(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        PROPERTIES EXPORT_COMPILE_COMMANDS OFF)
endif(BUILD_TESTS)

target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
                      ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
                      ${LOCALPROXY_OPENSSL_LINK})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
                      ${LOCALPROXY_BOOST_LINK})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
                      ${LOCALPROXY_PROTOBUF_LINK})
target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME} ${CMAKE_DL_LIBS})
# libatomic on every platform except OSX and WINDOWS, where it does not exist
lp_link_atomic(${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME})
set_property(
  TARGET ${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
  APPEND_STRING
  PROPERTY COMPILE_FLAGS ${CUSTOM_COMPILER_FLAGS})

if(BUILD_TESTS)
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        ${CMAKE_THREAD_LIBS_INIT})
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        ${LOCALPROXY_OPENSSL_LINK})
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        ${LOCALPROXY_BOOST_LINK})
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
                        ${LOCALPROXY_PROTOBUF_LINK})
  target_link_libraries(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME} ${CMAKE_DL_LIBS})
  lp_link_atomic(${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME})
  set_property(
    TARGET ${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
    APPEND_STRING
    PROPERTY COMPILE_FLAGS ${TEST_COMPILER_FLAGS})

  # Additive: CI and the docs still invoke bin/localproxytest directly.
  include(CTest)
  add_test(
    NAME ${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME}
    COMMAND
      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${AWS_TUNNEL_LOCAL_PROXY_TEST_NAME})
endif(BUILD_TESTS)

# ##############################################################################
# Section : Install #
# ##############################################################################
include(GNUInstallDirs)
install(TARGETS ${AWS_TUNNEL_LOCAL_PROXY_TARGET_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR})

if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/misc/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/misc/cmake_uninstall.cmake" IMMEDIATE @ONLY)
  add_custom_target(
    uninstall
    COMMAND ${CMAKE_COMMAND} -P
            "${CMAKE_CURRENT_BINARY_DIR}/misc/cmake_uninstall.cmake"
    COMMENT "Removing files listed in install_manifest.txt")
endif()
