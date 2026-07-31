# Dependency manifest loader and resolution policy.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# `fc_deps.json` at the repo root is the single source of truth for the pinned
# version, download URL and SHA256 of every dependency localproxy can build from
# source (Boost, Protobuf, Catch2). This module reads it and exposes each entry
# as a set of LP_DEP_<NAME>_<FIELD> variables, then resolves each dependency in
# one of two ways:
#
#   system  find_package() against pre-installed libraries. This is what every
#           Dockerfile, CI job and the documented `cmake ..` flow use today, and
#           it performs zero network access.
#   fetch   FetchContent the pinned tarball (integrity-checked with URL_HASH)
#           and add it to our build graph.
#
# LOCALPROXY_DEP_MODE selects between them; `auto` (the default) probes with
# find_package(... QUIET) first and only falls back to fetching if the
# dependency is genuinely absent. So a machine with the deps installed behaves
# exactly as it does today, and a bare machine can still build.
#
# OpenSSL and zlib deliberately never appear in the manifest. OpenSSL has no
# CMake build system (it configures with a Perl script) and README.md's policy
# is that it must come from the platform so that the local proxy uses the
# system's globally configured root CAs. zlib is only a transitive requirement
# -- nothing under src/ includes zlib.h.

include_guard(GLOBAL)

set(LOCALPROXY_MANIFEST
    "${CMAKE_SOURCE_DIR}/fc_deps.json"
    CACHE FILEPATH "Path to the dependency manifest")

# `string(JSON)` needs cmake 3.19. The root project deliberately keeps a lower
# minimum so that older distributions can still do a system-mode build, so the
# manifest is only parsed when the running cmake is new enough.
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.19)
  set(LOCALPROXY_MANIFEST_SUPPORTED TRUE)
else()
  set(LOCALPROXY_MANIFEST_SUPPORTED FALSE)
endif()

# Read fc_deps.json and set, for every dependency <dep>, the variables
# LP_DEP_NAMES (all keys, in manifest order) and LP_DEP_<DEP>_<FIELD> for each
# of VERSION, URL, SHA256, SUBDIR, WHEN, FIND_PACKAGE, FIND_VERSION,
# VERSION_VAR, LIBRARIES and OPTIONS. See fc_deps.json and docs/BUILD.md for
# what each field means; VERSION, URL and SHA256 are required, the rest are
# optional.
function(localproxy_load_manifest)
  if(NOT EXISTS "${LOCALPROXY_MANIFEST}")
    message(FATAL_ERROR "Dependency manifest not found: ${LOCALPROXY_MANIFEST}")
  endif()

  if(NOT LOCALPROXY_MANIFEST_SUPPORTED)
    # No string(JSON) before cmake 3.19, but the pinned versions must still
    # reach find_package: otherwise the Boost/Protobuf version floor and the
    # documented -D<DEP>_PKG_VERSION overrides silently vanish on exactly the
    # older distributions that the low CMake floor exists to support.
    #
    # Recover just the version/version_var pairs with a line scan. The manifest
    # is machine-formatted with one flat "field": "value" per line, and the
    # patterns below anchor on the leading quote so that "version" cannot match
    # inside "version_var" or "find_version".
    file(STRINGS "${LOCALPROXY_MANIFEST}" _lines)
    set(_version "")
    set(_pairs "")
    foreach(_line IN LISTS _lines)
      if(_line MATCHES "\"version\"[ \t]*:[ \t]*\"([^\"]*)\"")
        set(_version "${CMAKE_MATCH_1}")
      elseif(_line MATCHES "\"version_var\"[ \t]*:[ \t]*\"([^\"]*)\"")
        if(_version)
          list(APPEND _pairs "${CMAKE_MATCH_1}=${_version}")
        endif()
      endif()
    endforeach()
    set(LP_DEP_VERSION_PAIRS
        "${_pairs}"
        PARENT_SCOPE)
    return()
  endif()

  file(READ "${LOCALPROXY_MANIFEST}" _json)
  string(JSON _count LENGTH "${_json}")
  if(_count EQUAL 0)
    return()
  endif()
  math(EXPR _max "${_count} - 1")

  set(_names "")
  foreach(_index RANGE ${_max})
    string(JSON _dep MEMBER "${_json}" ${_index})
    list(APPEND _names "${_dep}")
    string(TOUPPER "${_dep}" _DEP)

    # Required fields.
    foreach(_field version url sha256)
      string(JSON _value GET "${_json}" "${_dep}" ${_field})
      string(TOUPPER "${_field}" _FIELD)
      set(LP_DEP_${_DEP}_${_FIELD}
          "${_value}"
          PARENT_SCOPE)
    endforeach()

    # Optional fields; a missing member sets the error variable rather than
    # failing the configure.
    foreach(
      _field
      subdir
      when
      find_package
      find_version
      find_components
      version_var
      libraries)
      string(
        JSON
        _value
        ERROR_VARIABLE
        _err
        GET
        "${_json}"
        "${_dep}"
        ${_field})
      if(_err)
        set(_value "")
      endif()
      string(TOUPPER "${_field}" _FIELD)
      set(LP_DEP_${_DEP}_${_FIELD}
          "${_value}"
          PARENT_SCOPE)
    endforeach()

    string(
      JSON
      _options
      ERROR_VARIABLE
      _err
      GET
      "${_json}"
      "${_dep}"
      options)
    if(_err)
      set(_options "{}")
    endif()
    set(LP_DEP_${_DEP}_OPTIONS
        "${_options}"
        PARENT_SCOPE)
  endforeach()

  set(LP_DEP_NAMES
      "${_names}"
      PARENT_SCOPE)
endfunction()

# Seed the default of each dependency's version cache variable from the
# manifest, so that fc_deps.json is the only place a pinned version is written
# down.
#
# An explicit -D on the command line still wins, including the empty string that
# every CI job passes to disable find_package's version assertion. The variables
# are intentionally *not* FORCEd for that reason.
function(localproxy_seed_version_cache)
  if(NOT LOCALPROXY_MANIFEST_SUPPORTED)
    # Fallback pairs recovered by localproxy_load_manifest's line scan.
    foreach(_pair IN LISTS LP_DEP_VERSION_PAIRS)
      if(_pair MATCHES "^([^=]+)=(.*)$")
        set(${CMAKE_MATCH_1}
            "${CMAKE_MATCH_2}"
            CACHE STRING "Version required by find_package (from fc_deps.json)")
      endif()
    endforeach()
    return()
  endif()

  foreach(_dep IN LISTS LP_DEP_NAMES)
    string(TOUPPER "${_dep}" _DEP)
    if(LP_DEP_${_DEP}_VERSION_VAR)
      set(${LP_DEP_${_DEP}_VERSION_VAR}
          "${LP_DEP_${_DEP}_VERSION}"
          CACHE STRING "Version of ${_dep} required by find_package")
    endif()
  endforeach()
endfunction()

# Resolve how `dep` should be provided, storing `system` or `fetch` in out_var.
#
# Precedence: LOCALPROXY_<DEP>_SOURCE, then LOCALPROXY_DEP_MODE. Under `auto` we
# probe for the dependency with find_package(... QUIET) and only fetch when it
# is not already available.
function(localproxy_resolve_mode dep out_var)
  string(TOUPPER "${dep}" _DEP)

  set(_mode "${LOCALPROXY_DEP_MODE}")
  if(LOCALPROXY_${_DEP}_SOURCE)
    set(_mode "${LOCALPROXY_${_DEP}_SOURCE}")
  endif()

  if(NOT _mode MATCHES "^(auto|system|fetch)$")
    message(FATAL_ERROR "Invalid dependency mode '${_mode}' for ${dep};"
                        " expected auto, system or fetch.")
  endif()

  if(_mode STREQUAL "fetch" OR _mode STREQUAL "auto")
    if(NOT LOCALPROXY_MANIFEST_SUPPORTED)
      if(_mode STREQUAL "fetch")
        message(
          FATAL_ERROR
            "Building dependencies from source needs CMake 3.19 or newer"
            " (found ${CMAKE_VERSION}). Run ./bootstrap-cmake.sh to obtain a"
            " pinned CMake, or install ${dep} and configure with"
            " -DLOCALPROXY_DEP_MODE=system.")
      endif()
      set(_mode "system")
    endif()
  endif()

  if(_mode STREQUAL "auto")
    if(LP_DEP_${_DEP}_FIND_PACKAGE)
      # Probe with exactly the constraint the REQUIRED find_package will later
      # assert, otherwise an installed-but-too-old copy is reported as found,
      # `auto` locks in system mode, and the real find_package hard-fails
      # instead of falling back to fetching.
      #
      # The version_var (BOOST_PKG_VERSION / PROTOBUF_PKG_VERSION) is the
      # authoritative constraint where one exists; find_version is the fallback
      # for dependencies without a cache variable (Catch2). Both are expanded
      # unquoted so that the documented empty-string value drops the argument
      # and probes version-agnostically, matching the real call.
      set(_probe_version "${LP_DEP_${_DEP}_FIND_VERSION}")
      if(LP_DEP_${_DEP}_VERSION_VAR)
        set(_probe_version "${${LP_DEP_${_DEP}_VERSION_VAR}}")
      endif()
      # find_components matters for Boost: a probe without them succeeds on a
      # headers-only install whose compiled libraries are missing, and the real
      # REQUIRED COMPONENTS call would then fail rather than fetching.
      set(_probe_components "")
      if(LP_DEP_${_DEP}_FIND_COMPONENTS)
        set(_probe_components COMPONENTS ${LP_DEP_${_DEP}_FIND_COMPONENTS})
      endif()
      # Probe in a child scope so a failed probe leaves no partial state behind.
      find_package(${LP_DEP_${_DEP}_FIND_PACKAGE} ${_probe_version} QUIET
                   ${_probe_components})
      if(${LP_DEP_${_DEP}_FIND_PACKAGE}_FOUND)
        set(_mode "system")
      else()
        set(_mode "fetch")
      endif()
    else()
      set(_mode "system")
    endif()
  endif()

  set(${out_var}
      "${_mode}"
      PARENT_SCOPE)
endfunction()

# Announce how a dependency was resolved. `auto` must never be opaque.
function(localproxy_report_mode dep mode)
  string(TOUPPER "${dep}" _DEP)
  if(mode STREQUAL "fetch")
    message(STATUS "localproxy: ${dep} -> fetch"
                   " (${LP_DEP_${_DEP}_VERSION}, from fc_deps.json)")
  else()
    message(STATUS "localproxy: ${dep} -> system (find_package)")
  endif()
endfunction()

# Apply a dependency's manifest `options` object as INTERNAL cache entries. Must
# run before the dependency's add_subdirectory so that its own option() calls
# pick these values up.
function(localproxy_apply_options dep)
  string(TOUPPER "${dep}" _DEP)
  set(_options "${LP_DEP_${_DEP}_OPTIONS}")

  string(JSON _count LENGTH "${_options}")
  if(_count EQUAL 0)
    return()
  endif()
  math(EXPR _max "${_count} - 1")

  foreach(_index RANGE ${_max})
    string(JSON _key MEMBER "${_options}" ${_index})
    string(JSON _value GET "${_options}" "${_key}")
    set(${_key}
        "${_value}"
        CACHE INTERNAL "Set by localproxy for ${dep}" FORCE)
  endforeach()
endfunction()

# Download (but do not add_subdirectory) a dependency's pinned source tree.
#
# SOURCE_SUBDIR names a directory that does not exist, which makes
# FetchContent_MakeAvailable populate the source and skip its add_subdirectory
# step -- the greengrass-lite trick, used here purely so that we can pre-set the
# dependency's cache options first and then add the subdirectory ourselves.
#
# Sets <dep>_SOURCE_DIR in the caller's scope. Point
# -DFETCHCONTENT_SOURCE_DIR_<DEP> at a local tree to skip the download entirely
# (vendored, air-gapped, Nix or cross-compiled dependency trees).
macro(localproxy_fetch dep)
  string(TOUPPER "${dep}" _lp_fetch_DEP)

  set(FETCHCONTENT_QUIET FALSE)
  include(FetchContent)

  # Land every tarball in one predictable directory. Without this, downloads go
  # to <dep>-subbuild/<dep>-populate-prefix/src/, whose layout is a FetchContent
  # implementation detail that has moved between CMake versions -- so CI cannot
  # reliably cache it. Keeping the archives together also lets an air-gapped
  # build pre-seed them by hand. This must be a DOWNLOAD_DIR argument: the
  # FETCHCONTENT_DOWNLOAD_DIR_<DEP> variable form is not honoured here.
  set(_lp_fetch_dl "${CMAKE_BINARY_DIR}/_deps/downloads")

  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    fetchcontent_declare(
      "${dep}"
      URL "${LP_DEP_${_lp_fetch_DEP}_URL}"
      URL_HASH SHA256=${LP_DEP_${_lp_fetch_DEP}_SHA256}
      DOWNLOAD_DIR "${_lp_fetch_dl}" DOWNLOAD_EXTRACT_TIMESTAMP TRUE
      SOURCE_SUBDIR lp_no_autoadd)
  else()
    fetchcontent_declare(
      "${dep}"
      URL "${LP_DEP_${_lp_fetch_DEP}_URL}"
      URL_HASH SHA256=${LP_DEP_${_lp_fetch_DEP}_SHA256}
      DOWNLOAD_DIR "${_lp_fetch_dl}" SOURCE_SUBDIR lp_no_autoadd)
  endif()

  fetchcontent_makeavailable(${dep})
  unset(_lp_fetch_dl)
  unset(_lp_fetch_DEP)
endmacro()
