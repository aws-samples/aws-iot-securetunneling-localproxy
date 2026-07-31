# OpenSSL dependency.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# OpenSSL is never built from source by this project and deliberately does not
# appear in fc_deps.json:
#
#   * it has no CMake build system (it configures with a Perl script), so
#     FetchContent could not build it anyway; and
#   * README.md's stated policy is that OpenSSL should come from the platform
#     package manager so that the local proxy uses the platform's globally
#     configured root CAs, and so that the distribution keeps tracking CVEs.
#
# No version constraint is applied: the documented support range is OpenSSL
# 1.0.1+ or OpenSSL 3, and adding a floor here would silently drop platforms.
#
# Exports:
#   LOCALPROXY_OPENSSL_LINK   what the executables should link

include_guard(GLOBAL)

if(LINK_STATIC_OPENSSL)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
  set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()
find_package(OpenSSL REQUIRED)

if(LINK_STATIC_OPENSSL)
  include_directories(${OPENSSL_INCLUDE_DIR})

  # Different OpenSSL installations and generators populate different imported
  # properties: OpenSSL 3 from Homebrew and multi-config MSVC in particular only
  # set the per-configuration variant, so the fallback is load-bearing.
  get_target_property(SSL_LOCATION OpenSSL::SSL IMPORTED_LOCATION)
  if(NOT SSL_LOCATION)
    get_target_property(SSL_LOCATION OpenSSL::SSL IMPORTED_LOCATION_RELEASE)
    if(NOT SSL_LOCATION)
      message(FATAL_ERROR "Could not find OpenSSL SSL library location")
    endif()
  endif()

  get_target_property(CRYPTO_LOCATION OpenSSL::Crypto IMPORTED_LOCATION)
  if(NOT CRYPTO_LOCATION)
    get_target_property(CRYPTO_LOCATION OpenSSL::Crypto
                        IMPORTED_LOCATION_RELEASE)
    if(NOT CRYPTO_LOCATION)
      message(FATAL_ERROR "Could not find OpenSSL Crypto library location")
    endif()
  endif()

  lp_static_lib_path(OpenSSL_STATIC_SSL_LIBRARY "${SSL_LOCATION}")
  lp_static_lib_path(OpenSSL_STATIC_CRYPTO_LIBRARY "${CRYPTO_LOCATION}")

  set(LOCALPROXY_OPENSSL_LINK "${OpenSSL_STATIC_SSL_LIBRARY}"
                              "${OpenSSL_STATIC_CRYPTO_LIBRARY}")
else()
  set(LOCALPROXY_OPENSSL_LINK OpenSSL::SSL OpenSSL::Crypto)
endif()
