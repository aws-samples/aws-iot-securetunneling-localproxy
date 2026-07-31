# Building the local proxy

The local proxy builds with CMake. There are two ways to satisfy its
dependencies, and the build picks between them automatically:

| Mode     | What it does                                                         |
| -------- | -------------------------------------------------------------------- |
| `system` | `find_package()` against pre-installed libraries. No network access. |
| `fetch`  | Downloads the versions pinned in `fc_deps.json` and builds them.     |
| `auto`   | Default. Probes for each library, fetches only what is missing.      |

So on a machine that already has Boost, Protobuf and Catch2 installed, nothing
has changed — `cmake .. && make` behaves exactly as it always has. On a bare
machine, the same command now works, because the missing pieces are fetched.

---

## Dependency manifest

`fc_deps.json` at the repository root is the single source of truth for every
dependency the build can compile from source. Bump a version there and both the
plain CMake build and CI move together.

Each entry has:

| Field             | Meaning                                                                         |
| ----------------- | ------------------------------------------------------------------------------- |
| `version`         | Pinned version. Seeds the `*_PKG_VERSION` cache variable.                       |
| `url`             | Release tarball URL.                                                            |
| `sha256`          | Tarball checksum, verified by CMake via `URL_HASH`.                             |
| `subdir`          | Subdirectory containing the dependency's `CMakeLists.txt`.                      |
| `find_package`    | Package name used in `system` mode.                                             |
| `find_version`    | Version constraint for the `auto` probe when there is no `version_var`.         |
| `find_components` | Components the `auto` probe must also find, so a partial install is not chosen. |
| `version_var`     | Cache variable whose default is seeded from `version`.                          |
| `libraries`       | Dependency-specific component list.                                             |
| `when`            | Option gating whether the dependency is needed at all.                          |
| `options`         | Cache values applied before the dependency's `add_subdirectory`.                |

The `auto` probe deliberately uses exactly the constraint the subsequent
`REQUIRED` `find_package` will assert — `version_var`'s value where one exists,
otherwise `find_version`, plus `find_components`. If it probed more loosely, an
installed-but-too-old or partially-installed dependency would be reported as
found and the real lookup would then fail instead of falling back to `fetch`.

Two entries in the manifest are load-bearing in non-obvious ways:

- **The Boost URL must be the GitHub `-cmake` release asset.** The
  `archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz` tarball, which
  the dependency-install instructions below use, contains **no root
  `CMakeLists.txt`** — it is a b2/Jamroot tree and cannot be added as a CMake
  subproject. Never fetch Boost from git either; the superproject has around 150
  submodules.
- **`BOOST_UUID_LINK_LIBATOMIC=OFF`.** Boost.UUID otherwise adds a bare `atomic`
  to its interface link libraries under GCC, and `src/main.cpp` includes
  `boost/uuid`. Without this, the resulting binary requires `libatomic.so.1` at
  run time even on hosts where that soname is absent.

### Dependencies that are deliberately _not_ in the manifest

- **OpenSSL.** It has no CMake build system (it configures with a Perl script),
  and the local proxy is documented to use the platform's globally configured
  root CAs — so it must come from the platform, which is also what keeps CVE
  tracking working. Install it with your package manager
  (`apt install libssl-dev`, `dnf install openssl-devel`,
  `brew install openssl@3`).
- **zlib.** Only a transitive requirement; nothing under `src/` includes
  `zlib.h`. In `fetch` mode Protobuf is configured with
  `protobuf_WITH_ZLIB=OFF`.

If you need a static OpenSSL on a machine with no packages:

```bash
curl -LO https://www.openssl.org/source/openssl-3.0.12.tar.gz
tar xzf openssl-3.0.12.tar.gz && cd openssl-3.0.12
./Configure --prefix="$PWD/../openssl-install" no-shared no-tests
make build_libs -j"$(nproc)" && make install_dev
```

Then pass `-DCMAKE_PREFIX_PATH=<that prefix>`.

---

## Build tools

- A C++14 compiler
- CMake **3.10 or newer** for a `system`-mode build
- CMake **3.19 or newer** for `fetch` mode (it uses CMake's JSON support)
- `make`, `git`, `curl`

If your CMake is too old for `fetch` mode, `./bootstrap-cmake.sh` downloads a
pinned CMake into the (git-ignored) `build/cmake/` directory and configures with
it. Extra arguments are passed straight through:

```bash
./bootstrap-cmake.sh -DBUILD_TESTS=ON
make -C build -j"$(nproc)"
```

The script supports Linux (x86_64, aarch64) and macOS. On Windows, install CMake
normally and follow `windows-localproxy-build.md`.

---

## Building

```bash
mkdir -p build && cd build
cmake ..
make -j"$(nproc)"
```

Outputs land at `build/bin/localproxy` and, with `-DBUILD_TESTS=ON`,
`build/bin/localproxytest`. Run the unit suite either way:

```bash
./bin/localproxytest      # what CI does
ctest --test-dir build    # equivalent, registered for convenience
```

`make install` installs only `localproxy`, into
`${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}` (i.e. `/usr/local/bin` by
default). `make -C build uninstall` removes whatever the last install recorded
in `install_manifest.txt`.

In-source builds are rejected; always configure into a separate directory. Any
directory matching `*build*/` is git-ignored.

---

## Configuration flags

### Project options

| Flag                          | Default  | Effect                                                                            |
| ----------------------------- | -------- | --------------------------------------------------------------------------------- |
| `BUILD_TESTS`                 | `OFF`    | Build the Catch2 unit tests in `test/` as `bin/localproxytest`.                   |
| `LINK_STATIC_OPENSSL`         | `ON`     | Statically link OpenSSL. `OFF` links the shared libraries instead.                |
| `GIT_VERSION`                 | `ON`     | Derive the version string from git history.                                       |
| `DISABLE_SSL_HOST_VERIFY_OPT` | `OFF`    | Compile out the `--no-ssl-host-verify` CLI option, for production builds.         |
| `BOOST_PKG_VERSION`           | manifest | Version passed to `find_package(Boost)`. Empty disables the version check.        |
| `PROTOBUF_PKG_VERSION`        | manifest | Version passed to `find_package(Protobuf)`. Empty disables the version check.     |
| `WIN32_WINNT`                 | `0x0A00` | Value of `_WIN32_WINNT`; must match the value Boost was built with. Windows only. |

### Dependency resolution

| Flag                                              | Default | Effect                                              |
| ------------------------------------------------- | ------- | --------------------------------------------------- |
| `LOCALPROXY_DEP_MODE`                             | `auto`  | `auto`, `system` or `fetch` for all dependencies.   |
| `LOCALPROXY_BOOST_SOURCE`                         | inherit | Per-dependency override of the above.               |
| `LOCALPROXY_PROTOBUF_SOURCE`                      | inherit | Per-dependency override of the above.               |
| `LOCALPROXY_CATCH2_SOURCE`                        | inherit | Per-dependency override of the above.               |
| `LOCALPROXY_LINK_ATOMIC`                          | `auto`  | `auto` probes; `ON`/`OFF` force linking `-latomic`. |
| `LOCALPROXY_PROTOC_EXECUTABLE`                    | unset   | Host `protoc` to use when cross-compiling.          |
| `FETCHCONTENT_SOURCE_DIR_{BOOST,PROTOBUF,CATCH2}` | unset   | Use a local source tree instead of downloading.     |
| `FETCHCONTENT_FULLY_DISCONNECTED`                 | `OFF`   | Forbid all downloads; requires the above.           |

Standard CMake variables (`CMAKE_BUILD_TYPE`, `CMAKE_PREFIX_PATH`,
`CMAKE_TOOLCHAIN_FILE`, `CMAKE_INSTALL_PREFIX`) behave as usual. Note there is
no default `CMAKE_BUILD_TYPE`: optimization comes from the hard-coded `-O2` in
the project's own compiler flags.

---

## Offline, vendored and air-gapped builds

Pre-fetch the dependency trees once, then point the build at them. No network
access happens at configure time:

```bash
cmake .. \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_BOOST=/opt/src/boost-1.87.0 \
  -DFETCHCONTENT_SOURCE_DIR_PROTOBUF=/opt/src/protobuf-3.17.3 \
  -DFETCHCONTENT_SOURCE_DIR_CATCH2=/opt/src/Catch2-3.7.0
```

This is also how a Nix derivation or a CI cache should feed the build.

---

## Cross-compilation

Cross builds default to `system` mode, because a toolchain file typically sets
`CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY` and expects every dependency to resolve
out of the sysroot:

```bash
cmake ../ -DCMAKE_TOOLCHAIN_FILE=raspberry_pi_3_b_plus.cmake.tc
make
```

See `example/crosscompile/raspberry_pi_3_b_plus.cmake.tc` for a worked example
and the README for the full walkthrough.

`fetch` mode can be combined with cross-compilation, but code generation needs a
`protoc` that runs on the **host** while the runtime library is built for the
**target**. Supply one explicitly:

```bash
cmake ../ -DCMAKE_TOOLCHAIN_FILE=<tc> -DLOCALPROXY_DEP_MODE=fetch \
          -DLOCALPROXY_PROTOC_EXECUTABLE=/usr/bin/protoc
```

Without it the configure fails with an explicit message rather than producing a
target binary that cannot be run.

---

## Static analysis and tooling

`CMAKE_EXPORT_COMPILE_COMMANDS` is on, so `build/compile_commands.json` is
always available for `clang-tidy`, `clangd` and IWYU. The test target is
excluded from the database, so each translation unit appears exactly once (with
the production flags) rather than twice with conflicting definitions.

Coverity uses the same build directory:

```bash
cmake -B build
coverity scan     # driven by coverity.json
```

---

## Formatting

`nix fmt` formats the tree — `clang-format` for C++, `cmake-format` for
`CMakeLists.txt`, `CMakeLists.txt.versioning` and `cmake/*.cmake`, `shfmt` for
shell scripts. CI requires a clean tree afterwards. See `AGENTS.md`.
