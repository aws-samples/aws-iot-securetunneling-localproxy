# Catch2 test framework dependency. Only needed when BUILD_TESTS is on.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Catch2 v2 and v3 have incompatible headers and target names; the tests include
# <catch2/catch_all.hpp> and rely on Catch2::Catch2WithMain to supply main(),
# which is why the test target excludes src/main.cpp. The major-version-3
# constraint is therefore essential.
#
# Exports:
#   LOCALPROXY_CATCH2_LINK   what the test executable should link
#   LOCALPROXY_CATCH2_MODE   system | fetch

include_guard(GLOBAL)

if(NOT BUILD_TESTS)
  return()
endif()

localproxy_resolve_mode(catch2 LOCALPROXY_CATCH2_MODE)
localproxy_report_mode(catch2 "${LOCALPROXY_CATCH2_MODE}")

if(LOCALPROXY_CATCH2_MODE STREQUAL "system")
  find_package(Catch2 3 REQUIRED)
else()
  localproxy_fetch(catch2)
  localproxy_apply_options(catch2)
  lp_add_dep_subdirectory("${catch2_SOURCE_DIR}" catch2-build)
endif()

set(LOCALPROXY_CATCH2_LINK Catch2::Catch2WithMain)
