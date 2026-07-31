# Boost dependency.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Exports:
#   LOCALPROXY_BOOST_LINK   what the executables should link
#   LOCALPROXY_BOOST_MODE   system | fetch

include_guard(GLOBAL)

localproxy_resolve_mode(boost LOCALPROXY_BOOST_MODE)
localproxy_report_mode(boost "${LOCALPROXY_BOOST_MODE}")

if(LOCALPROXY_BOOST_MODE STREQUAL "system")
  # Static Boost is what keeps the released binaries portable. Note these are
  # plain (non-cache) sets, so they win over a user-supplied
  # -DBoost_USE_STATIC_LIBS; that has always been the behavior here.
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_DEBUG_RUNTIME OFF)
  # set_property(GLOBAL PROPERTY Boost_USE_MULTITHREADED ON)

  # We rely on the deprecated FindBoost module (MODULE mode) because the
  # ${Boost_LIBRARIES} list below feeds the static-path rewrite. cmake 3.30
  # warns about this via CMP0167.
  if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
  endif()

  # ${BOOST_PKG_VERSION} is deliberately unquoted: every CI job passes
  # -DBOOST_PKG_VERSION="" and relies on the empty expansion dropping the
  # argument, turning this into a version-agnostic find_package.
  find_package(
    Boost ${BOOST_PKG_VERSION} REQUIRED
    COMPONENTS chrono
               date_time
               filesystem
               log
               log_setup
               program_options
               system
               thread)

  # SYSTEM: Boost.Log's headers contain constructs that trip -Werror (notably
  # -Wswitch-unreachable) under GCC. This used to work only by accident -- CI
  # installs Boost into the same prefix it marks SYSTEM for protobuf, so the
  # duplicate include directory was deduplicated away. Make it deliberate.
  include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

  # Never accumulate across re-configures.
  set(Boost_STATIC_LIBRARIES "")
  foreach(BOOST_LIB IN LISTS Boost_LIBRARIES)
    lp_static_lib_path(BOOST_STATIC_LIB "${BOOST_LIB}")
    list(APPEND Boost_STATIC_LIBRARIES "${BOOST_STATIC_LIB}")
  endforeach()

  set(LOCALPROXY_BOOST_LINK "${Boost_STATIC_LIBRARIES}")
else()
  localproxy_fetch(boost)

  # Prune the superproject to the libraries we actually use. Compiled-library
  # transitives (serialization, random, context, container, atomic, ...) are
  # resolved automatically, but header-only libraries such as beast, format and
  # uuid are not implied by the compiled components and must be listed.
  set(BOOST_INCLUDE_LIBRARIES
      "${LP_DEP_BOOST_LIBRARIES}"
      CACHE STRING "Boost libraries to configure" FORCE)

  # BOOST_UUID_LINK_LIBATOMIC=OFF (set from the manifest) matters: Boost.UUID
  # otherwise adds a bare `atomic` to its INTERFACE link libraries on GCC, and
  # src/main.cpp includes boost/uuid, which makes the resulting binary require
  # libatomic.so.1 at runtime even where that soname is absent.
  localproxy_apply_options(boost)

  if(MSVC)
    # Match the CRT the rest of the build uses; localproxy has always built
    # against the shared runtime (Boost_USE_DEBUG_RUNTIME is forced OFF).
    set(BOOST_RUNTIME_LINK
        shared
        CACHE INTERNAL "" FORCE)

    # Disable Boost's MSVC auto-linking. Boost headers emit #pragma comment(lib,
    # ...) naming a b2-style decorated import library
    # (libboost_log_setup-vc143-mt-x64-1_87.lib), but the Boost CMake build
    # produces undecorated names (libboost_log_setup.lib), so the linker fails
    # with LNK1104 on a file that was never created. CMake links the Boost::
    # targets explicitly, so the pragma is redundant as well as wrong.
    #
    # Only needed in fetch mode: a b2-built system Boost does carry the
    # decorated names that auto-linking expects.
    add_compile_definitions(BOOST_ALL_NO_LIB)
  endif()

  lp_boost_context_fix_vfp()

  lp_add_dep_subdirectory("${boost_SOURCE_DIR}" boost-build)

  # BUILD_SHARED_LIBS=OFF (from the manifest) already makes these static, so no
  # shared-to-static path rewriting is needed in this mode. boost_log also
  # carries BOOST_LOG_STATIC_LINK on its interface automatically.
  set(LOCALPROXY_BOOST_LINK
      Boost::chrono
      Boost::date_time
      Boost::filesystem
      Boost::log
      Boost::log_setup
      Boost::program_options
      Boost::system
      Boost::thread)

  # Header-only libraries the sources include directly.
  foreach(
    _hdr_lib
    algorithm
    asio
    beast
    config
    endian
    format
    lexical_cast
    optional
    phoenix
    property_tree
    regex
    uuid
    variant)
    if(TARGET Boost::${_hdr_lib})
      list(APPEND LOCALPROXY_BOOST_LINK Boost::${_hdr_lib})
    endif()
  endforeach()
endif()
