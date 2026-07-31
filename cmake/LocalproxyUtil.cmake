# Small, dependency-agnostic helpers shared by the LocalproxyXxx modules.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

include_guard(GLOBAL)

# Add a third-party source tree as a subproject, marking its interface include
# directories as SYSTEM so that our -Wall -Werror does not apply to the
# dependency's own headers.
#
# `SYSTEM` as an add_subdirectory keyword only exists in cmake >= 3.25, so for
# older cmake we walk the resulting targets and copy
# INTERFACE_INCLUDE_DIRECTORIES into INTERFACE_SYSTEM_INCLUDE_DIRECTORIES by
# hand.
function(lp_add_dep_subdirectory src_dir bin_dir)
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.25)
    add_subdirectory("${src_dir}" "${bin_dir}" EXCLUDE_FROM_ALL SYSTEM)
  else()
    add_subdirectory("${src_dir}" "${bin_dir}" EXCLUDE_FROM_ALL)
    lp_mark_system_includes("${src_dir}")
  endif()
endfunction()

# Recursively mark every target defined under `dir` as carrying SYSTEM include
# directories. Used as the pre-3.25 fallback for lp_add_dep_subdirectory.
function(lp_mark_system_includes dir)
  get_directory_property(_subdirs DIRECTORY "${dir}" SUBDIRECTORIES)
  foreach(_subdir IN LISTS _subdirs)
    lp_mark_system_includes("${_subdir}")
  endforeach()

  get_directory_property(_targets DIRECTORY "${dir}" BUILDSYSTEM_TARGETS)
  foreach(_target IN LISTS _targets)
    get_target_property(_aliased "${_target}" ALIASED_TARGET)
    if(_aliased)
      set(_target "${_aliased}")
    endif()
    get_target_property(_incs "${_target}" INTERFACE_INCLUDE_DIRECTORIES)
    if(_incs)
      set_property(
        TARGET "${_target}"
        APPEND
        PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${_incs})
    endif()
  endforeach()
endfunction()

# Replace a shared-library suffix with the static one, e.g.
# /usr/lib64/libprotobuf-lite.so -> /usr/lib64/libprotobuf-lite.a
#
# This reproduces the long-standing localproxy idiom for forcing static linkage
# of a library that find_package located as shared. Unlike the original it (a)
# tolerates empty and non-path inputs instead of hard-erroring, and (b) verifies
# that the rewritten path actually exists so that a failure surfaces here rather
# than as an opaque linker error.
function(lp_static_lib_path out_var lib_path)
  set(${out_var}
      "${lib_path}"
      PARENT_SCOPE)

  # string(REPLACE) errors out on an empty input, and FindBoost can hand us bare
  # linker flags such as `-pthread` rather than paths. Pass those through.
  if(NOT lib_path OR NOT IS_ABSOLUTE "${lib_path}")
    return()
  endif()

  # On MSVC both suffixes resolve to import/static `.lib` files, so the rewrite
  # is a no-op there and there is nothing to validate.
  if(CMAKE_SHARED_LIBRARY_SUFFIX STREQUAL CMAKE_STATIC_LIBRARY_SUFFIX)
    return()
  endif()

  string(REPLACE "${CMAKE_SHARED_LIBRARY_SUFFIX}"
                 "${CMAKE_STATIC_LIBRARY_SUFFIX}" _static "${lib_path}")

  if(NOT EXISTS "${_static}")
    message(
      FATAL_ERROR
        "Expected a static library at '${_static}' (derived from"
        " '${lib_path}'), but it does not exist. Install the static libraries"
        " for this dependency, configure with -DLOCALPROXY_DEP_MODE=fetch to"
        " build it from source, or link dynamically.")
  endif()

  set(${out_var}
      "${_static}"
      PARENT_SCOPE)
endfunction()

# Link libatomic to `target` when the toolchain needs it for 64-bit std::atomic.
#
# Historically localproxy linked the bare name `atomic` on every platform except
# Apple and MSVC. That is still the outer guard (libatomic does not exist on
# those two), but inside it we now feature-probe rather than assume: on x86-64
# glibc the library is unnecessary, while on 32-bit ARM it is required.
# LOCALPROXY_LINK_ATOMIC=ON restores the old unconditional behavior.
function(lp_link_atomic target)
  if(APPLE OR MSVC)
    return()
  endif()

  if(LOCALPROXY_LINK_ATOMIC STREQUAL "OFF")
    return()
  endif()

  if(NOT LOCALPROXY_LINK_ATOMIC STREQUAL "ON")
    lp_probe_libatomic()
    if(NOT LOCALPROXY_NEEDS_LIBATOMIC)
      return()
    endif()
  endif()

  target_link_libraries(${target} atomic)
endfunction()

# Set LOCALPROXY_NEEDS_LIBATOMIC in the caller's scope. Cached, so the two
# executables share one probe.
macro(lp_probe_libatomic)
  if(NOT DEFINED LOCALPROXY_NEEDS_LIBATOMIC)
    include(CheckCXXSourceCompiles)
    set(_lp_atomic_src
        "#include <atomic>
         #include <cstdint>
         int main() {
           std::atomic<std::uint64_t> v(0);
           v.fetch_add(1);
           return static_cast<int>(v.load());
         }")
    check_cxx_source_compiles("${_lp_atomic_src}" LP_ATOMIC_WITHOUT_LIBATOMIC)
    if(LP_ATOMIC_WITHOUT_LIBATOMIC)
      set(LOCALPROXY_NEEDS_LIBATOMIC
          FALSE
          CACHE INTERNAL "libatomic is required for 64-bit std::atomic")
    else()
      set(CMAKE_REQUIRED_LIBRARIES atomic)
      check_cxx_source_compiles("${_lp_atomic_src}" LP_ATOMIC_WITH_LIBATOMIC)
      unset(CMAKE_REQUIRED_LIBRARIES)
      if(NOT LP_ATOMIC_WITH_LIBATOMIC)
        message(WARNING "std::atomic<uint64_t> does not link with or without"
                        " -latomic; linking it anyway.")
      endif()
      set(LOCALPROXY_NEEDS_LIBATOMIC
          TRUE
          CACHE INTERNAL "libatomic is required for 64-bit std::atomic")
    endif()
    unset(_lp_atomic_src)
  endif()
endmacro()

# Give the assembler an explicit FPU on 32-bit ARM hard-float targets, where
# Boost.Context otherwise fails to assemble.
#
# Boost.Context's ARM/AAPCS sources save the VFP callee-saved registers with
# `vstmia sp, {d8-d15}` whenever the compiler defines __VFP_FP__ -- which it
# does on a hard-float port such as Debian/Ubuntu armhf. But those toolchains
# default to `-mfpu=auto`, which resolves against -march/-mcpu; with no -mcpu
# given it selects a CPU model with no VFP unit, and the assembler then rejects
# the very instructions the compiler asked for:
#
# Error: selected processor does not support `vstmia sp,{d8-d15}' in ARM mode
#
# Naming an FPU resolves the contradiction. vfpv3-d16 is the armv7-a hard-float
# baseline and covers exactly d0-d15, which is all these sources touch.
#
# Appends to CMAKE_ASM_FLAGS in the caller's scope. A user-supplied
# -DCMAKE_ASM_FLAGS is preserved, and the flag is only added once it has been
# shown to work, so an unusual toolchain degrades to the previous behavior
# instead of failing on an unknown option.
function(lp_boost_context_fix_vfp)
  if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|ARM)")
    return()
  endif()
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "64")
    return() # aarch64 always has an FPU; nothing to select.
  endif()
  if(CMAKE_ASM_FLAGS MATCHES "-mfpu=")
    return() # Respect an explicit choice.
  endif()

  # Probe with the C++ compiler rather than the ASM language: CMake compiles .S
  # files through the same driver (the CI log shows "Found assembler:
  # /usr/bin/cc"), ASM is not yet enabled at this point, and enable_language()
  # cannot be called from inside a function.
  if(NOT DEFINED LP_ASM_ACCEPTS_VFPV3_D16)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-mfpu=vfpv3-d16" LP_ASM_ACCEPTS_VFPV3_D16)
  endif()

  if(LP_ASM_ACCEPTS_VFPV3_D16)
    set(CMAKE_ASM_FLAGS
        "${CMAKE_ASM_FLAGS} -mfpu=vfpv3-d16"
        PARENT_SCOPE)
    message(STATUS "localproxy: 32-bit ARM detected, assembling Boost.Context"
                   " with -mfpu=vfpv3-d16")
  endif()
endfunction()
