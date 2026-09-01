# Building with Zig

This repository has two build systems. `CMakeLists.txt` is the supported one and
is what [docs/BUILD.md](BUILD.md) describes; nothing on this page changes it.
The Zig build (`build.zig` + `build.zig.zon`) sits alongside it and exists for
one capability CMake does not offer here: **one host toolchain that produces
binaries for every supported platform**, without installing a cross compiler, a
sysroot or a Docker image per target.

Requires **Zig 0.16.0**.

```bash
zig build                       # localproxy for the host  -> zig-out/bin/localproxy
zig build -Dtests test          # build and run the Catch2 unit suite
zig build -Dtarget=<triple>     # one cross target
zig build all                   # every target in the matrix
zig build deps                  # only the vendored third-party libraries
zig build test-build            # unit tests for the build logic in zig/
zig build --help                # every option
```

## The one thing you must supply: OpenSSL

**OpenSSL is never built from source by either build system.** The reasons are
in `cmake/LocalproxyOpenSSL.cmake` and unchanged here: OpenSSL configures with a
Perl script rather than a build system that can be driven from `build.zig`, and
`README.md`'s stated policy is that OpenSSL comes from the platform so the local
proxy uses the platform's globally configured root CAs and keeps tracking the
distribution's CVE fixes.

For a **host** build that means the platform package (`libssl-dev`,
`openssl-devel`, `brew install openssl@3`), discovered automatically.

For a **cross** build there is nothing to discover, so you must supply a
target-ABI OpenSSL. The build will not fall back to the host's libraries and
will not emit a binary it cannot link: it stops with a message naming both flags
and the triple.

```bash
# one target
zig build -Dtarget=aarch64-linux-gnu.2.17 \
          -Dopenssl-include=/path/to/aarch64/include \
          -Dopenssl-libdir=/path/to/aarch64/lib

# every target: one tree, per-triple subdirectories
zig build all -Dopenssl-sysroots=/path/to/openssl-roots
#   /path/to/openssl-roots/<triple>/include/openssl/opensslv.h
#   /path/to/openssl-roots/<triple>/lib/libssl.a  (and libcrypto.a)
```

`<triple>` is the **Target** column below. `-Dopenssl-sysroots` cannot be
combined with `-Dopenssl-include`/`-Dopenssl-libdir`: they are two ways of
saying the same thing, and honoring one silently would hide a mistake in the
other, so the build stops instead.

Under a prefix or a sysroot, `lib/<multiarch>`, `lib64` and `lib` are tried in
that order, and only a directory that actually contains `libssl`/`libcrypto` is
accepted. That order matters on Debian and Ubuntu, where `/usr/lib` always
exists but `libssl` lives in `/usr/lib/x86_64-linux-gnu`, and it is also the
layout a sysroot unpacked from a `.deb` has.

Where a per-target OpenSSL comes from is your choice; the usual sources are the
target distribution's own `-dev`/`-devel` package (unpack the `.deb`/`.rpm`), a
vendor SDK, or an OpenSSL you cross-build yourself with its own
`./Configure <target>`.

`-Dopenssl-static` defaults to `true`, mirroring `LINK_STATIC_OPENSSL=ON`, and
looks for `libssl.a` and `libcrypto.a`. Pass `-Dopenssl-static=false` to link a
shared OpenSSL instead.

## Target matrix

| Target                 | `-Dtarget=` value        | Notes                                |
| ---------------------- | ------------------------ | ------------------------------------ |
| `x86_64-linux-gnu`     | `x86_64-linux-gnu.2.17`  | glibc floor 2.17                     |
| `x86_64-linux-musl`    | `x86_64-linux-musl`      | static libc                          |
| `aarch64-linux-gnu`    | `aarch64-linux-gnu.2.17` | glibc floor 2.17                     |
| `aarch64-linux-musl`   | `aarch64-linux-musl`     | static libc                          |
| `arm-linux-gnueabihf`  | `arm-linux-gnueabihf`    | armv7l hard-float, v7-A + VFPv3-D16  |
| `arm-linux-musleabihf` | `arm-linux-musleabihf`   | armv7l hard-float                    |
| `aarch64-macos`        | `aarch64-macos`          | no Apple SDK needed for this project |
| `x86-windows-gnu`      | `x86-windows-gnu`        | 32-bit, clang/MinGW (not MSVC)       |

`zig build all` installs to `zig-out/bin/<Target>/localproxy`.

The glibc floors are deliberate: without a suffix Zig targets a recent glibc and
the resulting binary refuses to start on older distributions.

## Option parity with CMake

Every CMake option has one Zig option. Defaults match.

| CMake                          | Zig                                         | Default   |
| ------------------------------ | ------------------------------------------- | --------- |
| `BUILD_TESTS`                  | `-Dtests`                                   | `false`   |
| `LINK_STATIC_OPENSSL`          | `-Dopenssl-static`                          | `true`    |
| `LOCALPROXY_RELEASE`           | `-Drelease`                                 | `false`   |
| `DISABLE_SSL_HOST_VERIFY_OPT`  | `-Dno-ssl-host-verify-opt`                  | `false`   |
| `LOCALPROXY_DEP_MODE`          | `-Ddep-mode=auto\|system\|fetch`            | `auto`    |
| `LOCALPROXY_BOOST_SOURCE`      | `-Dboost-source=inherit\|system\|fetch`     | `inherit` |
| `LOCALPROXY_PROTOBUF_SOURCE`   | `-Dprotobuf-source=inherit\|system\|fetch`  | `inherit` |
| `LOCALPROXY_CATCH2_SOURCE`     | `-Dcatch2-source=inherit\|system\|fetch`    | `inherit` |
| `CMAKE_PREFIX_PATH`            | `-Ddep-prefix=<dir>[,<dir>...]`             | unset     |
| `LOCALPROXY_LINK_ATOMIC`       | `-Dlink-atomic=auto\|on\|off`               | `auto`    |
| `LOCALPROXY_PROTOC_EXECUTABLE` | `-Dprotoc=<path>`                           | (built)   |
| `WIN32_WINNT`                  | `-Dwin32-winnt=<hex>`                       | `0x0A00`  |
| (OpenSSL location)             | `-Dopenssl-include`, `-Dopenssl-libdir`     | (probed)  |
| (no equivalent)                | `-Dopenssl-sysroots=<dir>`                  | unset     |
| `CMAKE_BUILD_TYPE`             | `-Doptimize`                                | `Debug`   |
| `BOOST_PKG_VERSION`            | none -- version is fixed by `build.zig.zon` | --        |
| `PROTOBUF_PKG_VERSION`         | none -- version is fixed by `build.zig.zon` | --        |

`-Doptimize` selects Zig's own codegen defaults. It does **not** change the
`-O2 -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong -Wall -Werror` flag set
applied to this project's own translation units, which is unconditional in
`CMakeLists.txt` and unconditional here.

## Dependencies

`fc_deps.json` stays the single place a dependency version is decided.
`build.zig.zon` pins the **same** tarballs and versions; the `hash` values there
are Zig package multihashes, which are a different thing from the `sha256`
digests in `fc_deps.json` and cannot be copied across. Regenerate them with
`zig fetch --save=<name> <url>` (run from this directory -- `zig fetch` needs a
`build.zig` alongside it) whenever `fc_deps.json` is bumped.

| Dependency           | How                                                         |
| -------------------- | ----------------------------------------------------------- |
| OpenSSL              | system or `-Dopenssl-*` only; never fetched, never vendored |
| Boost 1.87.0         | compiled from the pinned tarball for the selected target    |
| Protobuf-lite 3.17.3 | compiled from the pinned tarball for the selected target    |
| Catch2 3.7.0         | compiled from the pinned tarball; only with `-Dtests`       |
| zlib                 | not used (`protobuf_WITH_ZLIB=OFF`, lite runtime)           |

All three fetched packages are lazy: a `-Ddep-mode=system` build downloads
nothing — including the `protoc` used for code generation, which comes from the
system in that mode — and Catch2 is fetched only when `-Dtests` is passed,
matching `fc_deps.json`'s `"when": "BUILD_TESTS"` gate.

`-Ddep-mode=auto` probes for a pre-installed Boost, protobuf or Catch2 and
compiles from source when one is missing or unusable. A pre-installed copy is
only used when **all** of the following hold, mirroring what
`cmake/LocalproxyDeps.cmake` gets from
`find_package(<dep> <version> COMPONENTS ...)`:

- **The selected target is the host, ABI and glibc floor included.** A system
  library is fixed to the configuration it was installed for, so it may not be
  linked into anything else. `-Dtarget=x86_64-linux-musl` on a glibc host is
  therefore _not_ a system-dependency candidate, and neither is
  `-Dtarget=x86_64-linux-gnu.2.17` (a different glibc floor) nor a bare
  `-Dtarget=x86_64-linux-gnu` (Zig resolves the unspecified glibc version on an
  explicit query to its own default, not to the host's). The same rule decides
  whether the platform OpenSSL may be used.
- **The headers report at least the pinned version** —
  `BOOST_VERSION >= 108700`, `GOOGLE_PROTOBUF_VERSION >= 3017003`,
  `CATCH_VERSION_MAJOR >= 3` (the major version is all
  `find_package(Catch2 3 REQUIRED)` asserts too).
- **Every library that will be linked is present** in one library directory
  under that prefix. A headers-only install falls through to `fetch` rather than
  failing at link time.

Prefixes searched, in order: any `-Ddep-prefix=<dir>[,<dir>...]` entries — this
build's stand-in for `CMAKE_PREFIX_PATH` — then `/usr`, `/usr/local`,
`/opt/homebrew`. Under each, `lib/<multiarch>`, `lib64` and `lib` are tried in
that order and the first one that actually holds the libraries wins. The prefix
that matched is passed on as `-isystem <prefix>/include` and `-L <libdir>`,
matching `include_directories(SYSTEM ${Boost_INCLUDE_DIRS})`; a directory the
compiler already searches (`/usr/include`) is left off, as CMake also does.

An explicit `-Ddep-mode=system` (or a per-dependency `-D<dep>-source=system`)
that cannot be satisfied is a configure error naming what was missing — it never
silently fetches instead. That mirrors `find_package(... REQUIRED)`.

Because none of this ever offers the host's headers to a cross target, a cross
build compiles Boost, protobuf and Catch2 from source. Only OpenSSL genuinely
needs a sysroot.

Boost, protobuf and Catch2 are compiled by mirroring each project's own
`CMakeLists.txt`: the same source lists, the same platform source selection and
the same compile definitions. Their headers reach this project's translation
units through `-isystem`, so `-Werror` never fires on a third-party header (the
same reason `cmake/LocalproxyBoost.cmake` uses `include_directories(SYSTEM ...)`
for Boost.Log). Their own translation units are compiled in separate modules
without `-Werror`.

### Protobuf code generation

`resources/Message.proto` is compiled by a **host** `protoc`, since it has to
run during the build. Which one follows the resolved dependency mode, as it does
in `cmake/LocalproxyProtobuf.cmake`:

- **fetch** — built from the same pinned 3.17.3 tree the runtime comes from,
  which is what guarantees the version match the generated `Message.pb.h`
  asserts at compile time.
- **system** — the `protoc` found on `PATH`, matching `protobuf_generate_cpp`.
  Generated code and runtime then both come from that one installation, so no
  separate version constraint is applied. The build stops with an actionable
  message if there is no `protoc`.
- `-Dprotoc=<path>` overrides both, in either mode; it must report 3.17.3, and
  the build stops if it does not.

Consequently the Zig build has no equivalent of the CMake build's
"cross-compiling in fetch mode needs `-DLOCALPROXY_PROTOC_EXECUTABLE`"
requirement: a host protoc is always available.

## Behavior differences worth knowing

These are deliberate, and each one is commented at the point it happens.

- **Windows is clang/MinGW, not MSVC.** `x86-windows-gnu` gets the GCC-style
  warning flags rather than `/W4 /analyze`, and — like CMake's WIN32 branch,
  which uses `/W4` with no `/WX` — warnings are **not** errors there: `-Werror`
  is applied to every other target and omitted for Windows. `/DYNAMICBASE` and
  `/NXCOMPAT` have no flag to pass: lld enables ASLR and DEP by default. Windows
  socket and crypto libraries (`ws2_32`, `mswsock`, `bcrypt`, `crypt32`,
  `advapi32`, `secur32`) are linked explicitly, because clang/MinGW does not act
  on the `#pragma comment(lib, ...)` directives in Boost's headers that an MSVC
  build relies on.
- **Boost.Log's Windows event log backend is off.** It needs
  `simple_event_log.h`/`.rc` generated by the message compiler
  (`windmc`/`mc.exe`), which is not part of the Zig toolchain. Boost's own
  `CMakeLists.txt` takes the same branch when it cannot find a message compiler.
- **Boost.Filesystem's feature probes are not run.** Upstream discovers `statx`,
  `sendfile`, `copy_file_range`, `dirent d_type` and friends with
  `check_cxx_source_compiles`; Zig has no configure-time compile probe, so those
  stay unset and Boost uses its portable fallbacks. One is decided rather than
  defaulted: for a glibc floor below 2.25 the build defines
  `BOOST_FILESYSTEM_DISABLE_GETRANDOM`, because Zig ships one recent set of
  glibc headers in which `<sys/random.h>` always exists but only declares
  `getrandom()` for glibc >= 2.25.
- **`-Dlink-atomic=auto` resolves to off.** Zig links its own `compiler_rt`,
  which supplies the out-of-line atomic helpers on every target in the matrix,
  so nothing needs `-latomic`. `lp_link_atomic()`'s compile probe has no
  equivalent; `-Dlink-atomic=on` remains available.
- **Clang's UBSan is disabled.** Zig enables it for C/C++ by default in `Debug`
  and `ReleaseSafe`. The CMake build never does, and trapping on undefined
  behavior is a runtime difference rather than a build-configuration one.
- **`Version.h` is synthesized directly** rather than substituted into
  `src/Version.h.in`. That template double-indirects through
  `${${PROJECT_NAME}_VERSION_STRING_FULL}` to cope with CMake's second
  `project()` call; the two macros it ultimately defines are emitted as-is. The
  version string, including the `git rev-parse --short=7 HEAD` suffix and its
  omission under `-Drelease`, is identical.
- **`zig build test` only runs the suite for a host target.** A cross-compiled
  test executable cannot execute on the build machine; for a cross target the
  step builds it and stops. "Host" here is the same strict comparison the
  dependency probes use, so `-Dtarget=x86_64-linux-gnu.2.17` counts as cross
  even on an x86_64 glibc machine. CMake's `add_test()` has the same limitation.
- **musl and 32-bit Windows have no CMake/CI precedent.** They are new
  configurations here rather than ports of an existing one.

## Known gaps

Deliberately not addressed yet; none of them changes the artifacts this build
produces today.

- `OPENSSL_ROOT_DIR` is not consulted; use
  `-Dopenssl-include`/`-Dopenssl-libdir` or `-Dopenssl-sysroots`.
- `SOURCE_DATE_EPOCH`/`ZERO_AR_DATE` are set on the build's own `Run` steps
  only, not on compile steps.
- `build.zig.zon`'s `.version` has to be updated by hand alongside the repo-root
  `version` file, which remains the single source of truth for what the binary
  reports.
- `zig build all` compiles Boost twice for the default target (once for the
  default build, once for that target's matrix entry).

## Reproducible builds

`SOURCE_DATE_EPOCH=0` and `ZERO_AR_DATE=1` are set on the build's own run steps,
mirroring `CMakeLists.txt`. Export them in CI as well if the surrounding tooling
needs them.

## Layout

```
build.zig          steps, options, the two executables
build.zig.zon      pinned Boost / Protobuf / Catch2 (same tarballs as fc_deps.json)
zig/config.zig     option types and shared helpers
zig/targets.zig    the target matrix
zig/system.zig     host-target and system-dependency discovery
zig/openssl.zig    system / sysroot OpenSSL resolution
zig/boost.zig      Boost 1.87.0
zig/protobuf.zig   protobuf-lite, host protoc, Message.proto codegen
zig/catch2.zig     Catch2 3.7.0 (test-only)
zig/version.zig    Version.h
zig/tests.zig      unit tests for the above (`zig build test-build`)
```

`zig fmt` formats `build.zig` and `zig/`; `nix fmt` does not cover Zig sources.
