# AWS IoT Secure Tunneling Local Proxy - Reference C++ implementation
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "AWS IoT Secure Tunneling Local Proxy";
  inputs.flakelight.url = "github:nix-community/flakelight";
  outputs = { flakelight, ... }@inputs: flakelight ./.
    ({ lib, ... }:
      {
        systems = lib.systems.flakeExposed;
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

        checks.spelling = pkgs: ''
          echo foo
          ${pkgs.nodePackages.cspell}/bin/cspell "**" --quiet
          ${pkgs.coreutils}/bin/sort -cuf misc/dictionary.txt
        '';
      });
}
