# Protobuf dependency: discovery, static-lib selection and codegen.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# resources/Message.proto sets `option optimize_for = LITE_RUNTIME`, so we link
# protobuf-lite rather than the full runtime.
#
# Exports:
#   LOCALPROXY_PROTOBUF_LINK   what the executables should link
#   LOCALPROXY_PROTOBUF_MODE   system | fetch

include_guard(GLOBAL)

localproxy_resolve_mode(protobuf LOCALPROXY_PROTOBUF_MODE)
localproxy_report_mode(protobuf "${LOCALPROXY_PROTOBUF_MODE}")

if(LOCALPROXY_PROTOBUF_MODE STREQUAL "system")
  # ${PROTOBUF_PKG_VERSION} is deliberately unquoted: every CI job passes
  # -DPROTOBUF_PKG_VERSION="" and relies on the empty expansion dropping the
  # argument entirely, turning this into find_package(Protobuf REQUIRED).
  find_package(Protobuf ${PROTOBUF_PKG_VERSION} REQUIRED)

  # Force static linkage of protobuf-lite even when find_package located the
  # shared library.
  lp_static_lib_path(Protobuf_LITE_STATIC_LIBRARY "${Protobuf_LITE_LIBRARY}")

  # SYSTEM so that protobuf's own headers, and the generated Message.pb.cc, are
  # exempt from our -Wall -Werror.
  include_directories(SYSTEM ${Protobuf_INCLUDE_DIRS})

  set(LOCALPROXY_PROTOBUF_LINK "${Protobuf_LITE_STATIC_LIBRARY}")
else()
  localproxy_fetch(protobuf)
  localproxy_apply_options(protobuf)

  # protobuf 3.17.3 keeps its CMakeLists.txt in the `cmake` subdirectory, which
  # is why the documented dependency build runs `cmake ../cmake`. This is the
  # textbook SOURCE_SUBDIR case.
  #
  # It also declares cmake_minimum_required(VERSION 3.1.3); newer cmake refuses
  # compatibility below 3.5 unless we relax the policy floor for the subproject.
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30 AND NOT
                                                  CMAKE_POLICY_VERSION_MINIMUM)
    set(CMAKE_POLICY_VERSION_MINIMUM
        3.5
        CACHE INTERNAL "Needed by protobuf 3.17.3" FORCE)
  endif()

  lp_add_dep_subdirectory("${protobuf_SOURCE_DIR}/cmake" pb-build)

  # protoc inherits CMAKE_RUNTIME_OUTPUT_DIRECTORY, which would drop a 13 MB
  # protoc next to localproxy in build/bin. Dockerfile copies build/bin/* into
  # the release image, so that must not happen.
  if(TARGET protoc)
    set_target_properties(protoc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            "${CMAKE_BINARY_DIR}/deps-bin")
  endif()

  set(LOCALPROXY_PROTOBUF_LINK protobuf::libprotobuf-lite)
endif()

# Generate C++ sources for the given .proto files into CMAKE_CURRENT_BINARY_DIR.
#
# src/TcpClient.h and friends use the unqualified #include "Message.pb.h", which
# resolves through include_directories(${CMAKE_CURRENT_BINARY_DIR}) -- so the
# output location is part of the contract and identical in both modes.
function(lp_protobuf_generate_cpp src_var hdr_var)
  if(LOCALPROXY_PROTOBUF_MODE STREQUAL "system")
    protobuf_generate_cpp(_srcs _hdrs ${ARGN})
    set(${src_var}
        "${_srcs}"
        PARENT_SCOPE)
    set(${hdr_var}
        "${_hdrs}"
        PARENT_SCOPE)
    return()
  endif()

  # Fetch mode: drive the protoc we just built. A target-built protoc cannot run
  # on the host, so cross-compilation needs either a host protoc or system mode.
  set(_protoc protobuf::protoc)
  if(LOCALPROXY_PROTOC_EXECUTABLE)
    set(_protoc "${LOCALPROXY_PROTOC_EXECUTABLE}")
  elseif(CMAKE_CROSSCOMPILING)
    message(
      FATAL_ERROR
        "Cross-compiling with -DLOCALPROXY_DEP_MODE=fetch requires a protoc"
        " that runs on the host. Pass -DLOCALPROXY_PROTOC_EXECUTABLE=<host"
        " protoc>, or install protobuf into the sysroot and use"
        " -DLOCALPROXY_PROTOBUF_SOURCE=system.")
  endif()

  set(_srcs "")
  set(_hdrs "")
  foreach(_proto IN LISTS ARGN)
    get_filename_component(_abs "${_proto}" ABSOLUTE)
    get_filename_component(_dir "${_abs}" DIRECTORY)
    get_filename_component(_name "${_abs}" NAME_WE)

    set(_src "${CMAKE_CURRENT_BINARY_DIR}/${_name}.pb.cc")
    set(_hdr "${CMAKE_CURRENT_BINARY_DIR}/${_name}.pb.h")

    add_custom_command(
      OUTPUT "${_src}" "${_hdr}"
      COMMAND ${_protoc} --cpp_out "${CMAKE_CURRENT_BINARY_DIR}" -I "${_dir}"
              "${_abs}"
      DEPENDS "${_abs}" ${_protoc}
      COMMENT "Running C++ protocol buffer compiler on ${_proto}"
      VERBATIM)

    list(APPEND _srcs "${_src}")
    list(APPEND _hdrs "${_hdr}")
  endforeach()

  set_source_files_properties(${_srcs} ${_hdrs} PROPERTIES GENERATED TRUE)
  set(${src_var}
      "${_srcs}"
      PARENT_SCOPE)
  set(${hdr_var}
      "${_hdrs}"
      PARENT_SCOPE)
endfunction()
