# Building the local proxy

CMake resolves each dependency by probing for an installed copy first and
fetching the version pinned in [`fc_deps.json`](../fc_deps.json) only if it is
missing. So `cmake .. && make` works both on a machine that already has the
libraries and on a bare one.

To install the dependencies by hand instead, see
[DEPENDENCIES.md](DEPENDENCIES.md). For Windows, see
[windows-localproxy-build.md](../windows-localproxy-build.md). To skip building
altogether, use the prebuilt images in [DOCKER.md](DOCKER.md).

## Requirements

| Tool / library | Version                                                    |
| -------------- | ---------------------------------------------------------- |
| C++ compiler   | C++14                                                      |
| CMake          | 3.10+ (`system` mode); 3.19+ to fetch dependencies         |
| OpenSSL        | 1.0.1+ or 3.x — **always from your platform**              |
| zlib           | 1.2.13+ — **always from your platform**                    |
| Boost          | 1.87.0 — installed or fetched                              |
| Protobuf       | 3.17.3 — installed or fetched                              |
| Catch2         | 3.7.0 — installed or fetched, only with `-DBUILD_TESTS=ON` |

You also need `make`, `git` and `curl`.

Bump a fetched version in `fc_deps.json`; it is the single source of truth.
OpenSSL and zlib are deliberately absent from it: OpenSSL has no CMake build and
the proxy must use the platform's root CAs, and zlib is only a transitive
requirement (`protobuf_WITH_ZLIB=OFF` in `fetch` mode).

If your CMake is too old to fetch, `./bootstrap-cmake.sh` downloads a pinned one
into `build/cmake/` and configures with it, passing extra arguments through:

```bash
./bootstrap-cmake.sh -DBUILD_TESTS=ON
make -C build -j"$(nproc)"
```

## Building

```bash
git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy
cd aws-iot-securetunneling-localproxy
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

`make install` installs only `localproxy`, into `/usr/local/bin` by default;
`make -C build uninstall` reverses it. In-source builds are rejected; any
directory matching `*build*/` is git-ignored.

The same source builds both source and destination mode — copy or distribute the
`localproxy` binary as you please.

### Building without pre-installed dependencies

Install only OpenSSL and zlib, then build normally:

```bash
# Debian/Ubuntu
sudo apt install -y build-essential cmake git curl libssl-dev zlib1g-dev

mkdir build && cd build
cmake ..
make -j"$(nproc)"
```

The first such build downloads roughly 140 MB. Requires CMake 3.19+.

### Offline, vendored and air-gapped builds

Pre-fetch the dependency trees once, then point the build at them — no network
access at configure time:

```bash
cmake .. \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_BOOST=/opt/src/boost-1.87.0 \
  -DFETCHCONTENT_SOURCE_DIR_PROTOBUF=/opt/src/protobuf-3.17.3 \
  -DFETCHCONTENT_SOURCE_DIR_CATCH2=/opt/src/Catch2-3.7.0
```

### Cross-compilation

Cross builds default to `system` mode, expecting every dependency in the
sysroot. Supply a toolchain file — see
`example/crosscompile/raspberry_pi_3_b_plus.cmake.tc`:

```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=raspberry_pi_3_b_plus.cmake.tc
make -j"$(nproc)"
```

With `fetch` mode, code generation also needs a `protoc` that runs on the
**host** while the runtime library is built for the **target**:

```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=<tc> -DLOCALPROXY_DEP_MODE=fetch \
         -DLOCALPROXY_PROTOC_EXECUTABLE=/usr/bin/protoc
```

## Configuration flags

| Flag                          | Default  | Effect                                                                            |
| ----------------------------- | -------- | --------------------------------------------------------------------------------- |
| `BUILD_TESTS`                 | `OFF`    | Build the Catch2 unit tests in `test/` as `bin/localproxytest`.                   |
| `LINK_STATIC_OPENSSL`         | `ON`     | Statically link OpenSSL. `OFF` links the shared libraries instead.                |
| `GIT_VERSION`                 | `ON`     | Derive the version string from git history.                                       |
| `DISABLE_SSL_HOST_VERIFY_OPT` | `OFF`    | Compile out the `--no-ssl-host-verify` CLI option, for production builds.         |
| `BOOST_PKG_VERSION`           | manifest | Version passed to `find_package(Boost)`. Empty disables the version check.        |
| `PROTOBUF_PKG_VERSION`        | manifest | Version passed to `find_package(Protobuf)`. Empty disables the version check.     |
| `WIN32_WINNT`                 | `0x0A00` | Value of `_WIN32_WINNT`; must match the value Boost was built with. Windows only. |

| Flag                                              | Default | Effect                                              |
| ------------------------------------------------- | ------- | --------------------------------------------------- |
| `LOCALPROXY_DEP_MODE`                             | `auto`  | `auto`, `system` or `fetch` for all dependencies.   |
| `LOCALPROXY_{BOOST,PROTOBUF,CATCH2}_SOURCE`       | inherit | Per-dependency override of the above.               |
| `LOCALPROXY_LINK_ATOMIC`                          | `auto`  | `auto` probes; `ON`/`OFF` force linking `-latomic`. |
| `LOCALPROXY_PROTOC_EXECUTABLE`                    | unset   | Host `protoc` to use when cross-compiling.          |
| `FETCHCONTENT_SOURCE_DIR_{BOOST,PROTOBUF,CATCH2}` | unset   | Use a local source tree instead of downloading.     |
| `FETCHCONTENT_FULLY_DISCONNECTED`                 | `OFF`   | Forbid all downloads; requires the above.           |

Standard CMake variables (`CMAKE_BUILD_TYPE`, `CMAKE_PREFIX_PATH`,
`CMAKE_TOOLCHAIN_FILE`, `CMAKE_INSTALL_PREFIX`) behave as usual. There is no
default `CMAKE_BUILD_TYPE`: optimization comes from the project's hard-coded
`-O2`. We also recommend enabling your compiler's security features — see
[Harden your toolchain](SECURITY.md#harden-your-toolchain).

## Tooling

`build/compile_commands.json` is always generated for `clang-tidy`, `clangd` and
IWYU, with the test target excluded so each translation unit appears once.
Coverity uses the same build directory (`cmake -B build && coverity scan`,
driven by `coverity.json`). `nix fmt` formats the tree and CI requires it to be
clean — see [AGENTS.md](../AGENTS.md).

## Editing `fc_deps.json`

- **Boost's URL must stay the GitHub `-cmake` release asset.** The
  `archives.boost.io` tarball has no root `CMakeLists.txt`, and Boost's git
  superproject has ~150 submodules — neither can be a CMake subproject.
- **Keep `BOOST_UUID_LINK_LIBATOMIC=OFF`.** Otherwise Boost.UUID adds a bare
  `atomic` to its interface link libraries under GCC and the binary requires
  `libatomic.so.1` at run time.
