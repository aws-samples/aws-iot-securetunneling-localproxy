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
        formatters = { llvmPackages, cmake-format, prettier, shfmt, ... }:
          let
            fmt-cpp = "${llvmPackages.clang-unwrapped}/bin/clang-format -i";
            fmt-cmake = "${cmake-format}/bin/cmake-format -i";
            fmt-yaml = "${prettier}/bin/prettier --write --parser yaml";
            fmt-sh = "${shfmt}/bin/shfmt -w";
          in
          {
            "*.cpp" = fmt-cpp;
            "*.h" = fmt-cpp;
            "*.hpp" = fmt-cpp;
            "CMakeLists.txt" = fmt-cmake;
            "*.cmake" = fmt-cmake;
            ".clang*" = fmt-yaml;
            "*.sh" = fmt-sh;
          };

        checks.spelling = pkgs: ''
          echo foo
          ${pkgs.cspell}/bin/cspell "**" --quiet
          ${pkgs.coreutils}/bin/sort -cuf misc/dictionary.txt
        '';

        # fc_deps.json is the single source of truth for pinned dependency
        # versions; keep it valid JSON with the fields the CMake loader reads.
        checks.manifest = pkgs: ''
          ${pkgs.jq}/bin/jq -e 'to_entries | all(.value |
            has("version") and has("url") and has("sha256"))' \
            fc_deps.json > /dev/null
        '';

        # Keep the cmake/ modules lint-clean under .cmake-format.json. Scoped to
        # cmake/ deliberately: the root CMakeLists.txt and the versioning module
        # carry pre-existing long-line findings that predate this check.
        checks.cmake-lint = pkgs: ''
          ${pkgs.cmake-format}/bin/cmake-lint --suppress-decorations \
            cmake/*.cmake
        '';
      });
}
