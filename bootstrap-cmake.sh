#!/bin/sh
# Download a pinned CMake into build/cmake and configure the project with it.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Building the dependencies from source (-DLOCALPROXY_DEP_MODE=fetch) needs
# CMake 3.19 or newer for its JSON support. Distributions such as Amazon Linux 2
# ship an older cmake, so this script fetches a known-good release into the
# (git-ignored) build directory rather than installing anything system-wide.
#
# Any extra arguments are passed straight through to cmake, e.g.
#   ./bootstrap-cmake.sh -DBUILD_TESTS=ON -DLINK_STATIC_OPENSSL=OFF

set -eu

cmake_version=3.30.2

os=$(uname -s)
arch=$(uname -m)

case "${os}" in
  Linux)
    case "${arch}" in
      x86_64 | aarch64)
        cmake_name="cmake-${cmake_version}-linux-${arch}"
        cmake_rel_bin="${cmake_name}/bin/cmake"
        ;;
      *)
        echo "Bootstrap script does not support Linux arch: ${arch}." >&2
        exit 1
        ;;
    esac
    ;;
  Darwin)
    cmake_name="cmake-${cmake_version}-macos-universal"
    cmake_rel_bin="${cmake_name}/CMake.app/Contents/bin/cmake"
    ;;
  *)
    echo "Bootstrap script does not support OS: ${os}." >&2
    echo "On Windows, install CMake from https://cmake.org/download/ and see docs/windows-localproxy-build.md." >&2
    exit 1
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "${script_dir}"

mkdir -p build/cmake

cmake_bin="build/cmake/${cmake_rel_bin}"

if [ ! -x "${cmake_bin}" ]; then
  cmake_url="https://github.com/Kitware/CMake/releases/download/v${cmake_version}/${cmake_name}.tar.gz"
  echo "Downloading ${cmake_url}"
  curl -fsSL "${cmake_url}" | tar xz -C build/cmake/
fi

echo "Configuring with $("${cmake_bin}" --version | head -n 1)"
exec "${cmake_bin}" -S . -B build "$@"
