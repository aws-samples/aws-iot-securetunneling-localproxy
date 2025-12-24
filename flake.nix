# AWS IoT Secure Tunneling Local Proxy - Reference C++ implementation
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "AWS IoT Secure Tunneling Local Proxy";
  inputs.flakelight.url = "github:nix-community/flakelight";
  outputs = { flakelight, ... }@inputs: flakelight ./.
    ({ lib, config, ... }:
      let
        inherit (lib) mapAttrsToList toUpper;

        filteredSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./CMakeLists.txt
            ./CMakeLists.txt.versioning
            ./src
            ./resources
            ./test
            ./.clang-tidy
            ./.version
          ];
        };

        llvmStdenv = pkgs: pkgs.overrideCC pkgs.llvmPackages.stdenv
          (pkgs.llvmPackages.stdenv.cc.override
            { inherit (pkgs.llvmPackages) bintools; });

      in
      {
        systems = lib.systems.flakeExposed;
        inherit inputs;

        devShell = pkgs: {
          packages = with pkgs; [
            clang-tools
            cmake
            ninja
            pkg-config
            boost
            protobuf
            openssl
            catch2_3
            git
          ];
          env.NIX_HARDENING_ENABLE = "";
          shellHook = ''
            export MAKEFLAGS=-j
          '';
        };

        devShells.clang = { lib, pkgs, ... }: {
          imports = [ (config.devShell pkgs) ];
          stdenv = lib.mkForce (llvmStdenv pkgs);
        };

        formatters = { llvmPackages, cmake-format, nodePackages, ... }:
          let
            fmt-cpp = "${llvmPackages.clang-unwrapped}/bin/clang-format -i";
            fmt-cmake = "${cmake-format}/bin/cmake-format -i";
            fmt-yaml = "${nodePackages.prettier}/bin/prettier --write --parser yaml";
          in
          {
            "*.cpp" = fmt-cpp;
            "*.h" = fmt-cpp;
            "*.hpp" = fmt-cpp;
            "CMakeLists.txt" = fmt-cmake;
            ".clang*" = fmt-yaml;
          };

        pname = "localproxy";
        package = { pkgs, lib, stdenv, cmake, ninja, pkg-config, boost, protobuf, openssl, defaultMeta }:
          stdenv.mkDerivation {
            name = "localproxy";
            src = filteredSrc;
            nativeBuildInputs = [ cmake ninja pkg-config ];
            buildInputs = [ boost protobuf openssl ];
            cmakeBuildType = "Release";
            cmakeFlags = [
              "-DBUILD_TESTS=OFF"
              "-DLINK_STATIC_OPENSSL=OFF"
              "-DGIT_VERSION=OFF"
            ];
            meta = defaultMeta;
          };

        checks =
          let
            clangBuildDir = { pkgs, pkg-config, clang-tools, boost, protobuf, openssl, cmake, ... }:
              (llvmStdenv pkgs).mkDerivation {
                name = "clang-cmake-build-dir";
                nativeBuildInputs = [ pkg-config clang-tools cmake ];
                buildInputs = [ boost protobuf openssl ];
                buildPhase = ''
                  ${cmake}/bin/cmake -B $out -S ${filteredSrc} \
                    -D CMAKE_BUILD_TYPE=Debug \
                    -D BUILD_TESTS=OFF \
                    -D LINK_STATIC_OPENSSL=OFF \
                    -D GIT_VERSION=OFF \
                    -D CMAKE_EXPORT_COMPILE_COMMANDS=ON
                  rm -f $out/CMakeFiles/CMakeConfigureLog.yaml
                '';
                dontUnpack = true;
                dontPatch = true;
                dontConfigure = true;
                dontInstall = true;
                dontFixup = true;
                allowSubstitutes = false;
              };
          in
          {
            build-clang = pkgs: pkgs.localproxy.override
              { stdenv = llvmStdenv pkgs; };

            clang-tidy = pkgs: ''
              set -eo pipefail
              PATH=${lib.makeBinPath (with pkgs; [clangd-tidy clang-tools fd])}:$PATH
              clangd-tidy -j$(nproc) -p ${clangBuildDir pkgs} --color=always \
                $(fd . ${filteredSrc}/src -e cpp -e h -e hpp) |\
                sed 's|\.\.${filteredSrc}/||'
            '';

            cmake-lint = pkgs: ''
              ${pkgs.cmake-format}/bin/cmake-lint \
                ${filteredSrc}/CMakeLists.txt \
                --suppress-decorations
            '';

            spelling = pkgs: ''
              ${pkgs.nodePackages.cspell}/bin/cspell "**" --quiet
              ${pkgs.coreutils}/bin/sort -cuf misc/dictionary.txt
            '';
          };

        withOverlays = final: prev: {
          clangd-tidy = final.callPackage
            ({ python3Packages }:
              python3Packages.buildPythonPackage rec {
                pname = "clangd_tidy";
                version = "1.1.0.post1";
                format = "pyproject";
                src = final.fetchPypi {
                  inherit pname version;
                  hash = "sha256-wqwrdD+8kd2N0Ra82qHkA0T2LjlDdj4LbUuMkTfpBww=";
                };
                buildInputs = with python3Packages; [ setuptools-scm ];
                propagatedBuildInputs = with python3Packages; [
                  attrs
                  cattrs
                  typing-extensions
                ];
              })
            { };
        };
      });
}
