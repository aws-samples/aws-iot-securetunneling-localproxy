// Zig build for the AWS IoT Secure Tunneling local proxy.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This sits *alongside* CMakeLists.txt; neither build reads the other's files
// and neither is authoritative over the other. CMakeLists.txt remains the
// supported build (see docs/BUILD.md). The Zig build exists for one reason the
// CMake build cannot offer: a single host toolchain that produces binaries for
// every triple in zig/targets.zig without a per-target cross toolchain.
//
// What is intentionally identical to CMake:
//   * C++14, no compiler extensions (CMAKE_CXX_STANDARD 14 / EXTENSIONS OFF).
//   * The exact -O2 -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong
//     -Wall -Werror flag set on our own translation units.
//   * The deliberate double-compile of CORE+UTIL for localproxy and
//     localproxytest -- see the long comment in CMakeLists.txt and below.
//   * Every user-facing option, one Zig option per CMake option
//     (docs/ZIG_BUILD.md has the parity table).
//   * OpenSSL is never built from source; it comes from the system or a
//     user-supplied sysroot, as in cmake/LocalproxyOpenSSL.cmake.
//   * Reproducible-build environment (SOURCE_DATE_EPOCH=0, ZERO_AR_DATE=1).
//
// What is intentionally different, and why:
//   * Boost, protobuf-lite and Catch2 are compiled from the pinned sources by
//     this build rather than by their own CMake, so that one toolchain covers
//     every target. The versions and tarballs are the ones in fc_deps.json.
//   * `x86-windows-gnu` is clang/MinGW, not MSVC, so it takes the GCC-style
//     warning flags rather than /W4 /analyze. /DYNAMICBASE and /NXCOMPAT have
//     no MinGW equivalent to pass: lld enables ASLR and DEP by default.
//   * Windows socket libraries are named explicitly; see linkWindowsLibs.

const std = @import("std");

const cfg = @import("zig/config.zig");
const targets = @import("zig/targets.zig");
const version = @import("zig/version.zig");
const openssl = @import("zig/openssl.zig");
const boost = @import("zig/boost.zig");
const protobuf = @import("zig/protobuf.zig");
const catch2 = @import("zig/catch2.zig");

/// src/config/ConfigFile.cpp, src/Url.cpp, src/InputValidation.cpp
/// (UTIL_SOURCE in CMakeLists.txt).
const util_sources = [_][]const u8{
    "src/config/ConfigFile.cpp",
    "src/Url.cpp",
    "src/InputValidation.cpp",
};

/// CORE_SOURCES in CMakeLists.txt, minus the generated protobuf source (which
/// is added separately because it lives in the build directory).
const core_sources = [_][]const u8{
    "src/TcpAdapterProxy.cpp",
    "src/ProxySettings.cpp",
    "src/WebProxyAdapter.cpp",
    "src/WebSocketStream.cpp",
};

const main_source = "src/main.cpp";

/// test/*.cpp -- CMakeLists.txt globs these with CONFIGURE_DEPENDS. Zig has no
/// glob, and an explicit list is checked by the compiler the moment a file is
/// renamed, so enumerate them.
const test_sources = [_][]const u8{
    "test/AdapterTests.cpp",
    "test/TestHttpServer.cpp",
    "test/TestWebsocketServer.cpp",
    "test/Url.cpp",
    "test/WebProxyAdapterTests.cpp",
};

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const options = cfg.Options{
        // BUILD_TESTS
        .tests = b.option(bool, "tests", "Build tests") orelse false,
        // LINK_STATIC_OPENSSL
        .openssl_static = b.option(bool, "openssl-static", "Use static openssl libs") orelse true,
        // LOCALPROXY_RELEASE
        .release = b.option(
            bool,
            "release",
            "Build as release version without git hash",
        ) orelse false,
        // DISABLE_SSL_HOST_VERIFY_OPT
        .no_ssl_host_verify_opt = b.option(
            bool,
            "no-ssl-host-verify-opt",
            "Disable the --no-ssl-host-verify option for production builds",
        ) orelse false,
        // LOCALPROXY_DEP_MODE
        .dep_mode = b.option(
            cfg.DepMode,
            "dep-mode",
            "Dependency resolution for Boost/Protobuf/Catch2: auto, system or fetch",
        ) orelse .auto,
        // LOCALPROXY_BOOST_SOURCE
        .boost_source = b.option(
            cfg.DepSource,
            "boost-source",
            "Override dependency mode for Boost",
        ) orelse .inherit,
        // LOCALPROXY_PROTOBUF_SOURCE
        .protobuf_source = b.option(
            cfg.DepSource,
            "protobuf-source",
            "Override dependency mode for Protobuf",
        ) orelse .inherit,
        // LOCALPROXY_CATCH2_SOURCE
        .catch2_source = b.option(
            cfg.DepSource,
            "catch2-source",
            "Override dependency mode for Catch2",
        ) orelse .inherit,
        // LOCALPROXY_LINK_ATOMIC
        .link_atomic = b.option(
            cfg.LinkAtomic,
            "link-atomic",
            "Link libatomic: auto, on or off",
        ) orelse .auto,
        // LOCALPROXY_PROTOC_EXECUTABLE
        .protoc = b.option(
            []const u8,
            "protoc",
            "Host protoc to use for codegen (must be " ++ protobuf.pinned_version ++ ")",
        ),
        // WIN32_WINNT
        .win32_winnt = b.option(
            []const u8,
            "win32-winnt",
            "Value of _WIN32_WINNT to compile against (Windows only)",
        ) orelse "0x0A00",
        .openssl_include = b.option(
            []const u8,
            "openssl-include",
            "Directory containing openssl/opensslv.h for the selected target",
        ),
        .openssl_libdir = b.option(
            []const u8,
            "openssl-libdir",
            "Directory containing libssl/libcrypto for the selected target",
        ),
        .openssl_sysroots = b.option(
            []const u8,
            "openssl-sysroots",
            "Root of per-target OpenSSL trees: <dir>/<triple>/{include,lib}",
        ),
        .optimize = optimize,
    };

    // Same validation as CMakeLists.txt's WIN32_WINNT check, applied for every
    // target so a typo is caught even when the Windows build is not selected.
    if (!isHexLiteral(options.win32_winnt)) cfg.fatal(
        "-Dwin32-winnt must be a hexadecimal Windows API version such as 0x0A00, got '{s}'",
        .{options.win32_winnt},
    );

    // Version.h is target-independent, so generate it once.
    const version_dir = version.generate(b, options.release);

    // Protobuf codegen runs once on the host and is shared by every target;
    // generated C++ is target-independent.
    const generated = protobuf.generate(b, options) orelse return;

    // -------- default target --------------------------------------------
    const default_target = b.standardTargetOptions(.{});
    // Built once and shared with the `deps` step below, so asking for both in
    // one invocation does not compile Boost twice.
    const default_deps = addDeps(b, options, default_target) orelse return;
    const default = addTarget(
        b,
        options,
        default_target,
        version_dir,
        generated,
        default_deps,
    ) orelse return;
    switch (default) {
        .built => |built| {
            b.installArtifact(built.exe);
            if (built.test_exe) |t| b.installArtifact(t);
        },
        // No OpenSSL: the install (default) step fails with the message rather
        // than emitting a binary that cannot link. `zig build deps` below is
        // unaffected, which is what makes a cross build verifiable without a
        // sysroot.
        .no_openssl => |message| b.getInstallStep().dependOn(&b.addFail(message).step),
    }

    // -------- `zig build test` ------------------------------------------
    // A cross-compiled test executable cannot run on the host, so this step
    // runs the suite only when the selected target is the host. CMake's
    // add_test() has the same limitation, enforced by CTest at run time.
    const test_step = b.step("test", "Build and run the Catch2 unit tests");
    switch (default) {
        .no_openssl => |message| test_step.dependOn(&b.addFail(message).step),
        .built => |built| if (built.test_exe) |t| {
            if (isHostTarget(b, default_target)) {
                const run = b.addRunArtifact(t);
                run.setEnvironmentVariable("SOURCE_DATE_EPOCH", "0");
                run.setEnvironmentVariable("ZERO_AR_DATE", "1");
                test_step.dependOn(&run.step);
            } else {
                // Still build it, so a cross `-Dtests` build is verified.
                test_step.dependOn(&t.step);
            }
        } else {
            test_step.dependOn(&b.addFail(
                "zig build test requires -Dtests (mirrors BUILD_TESTS=ON)",
            ).step);
        },
    }

    // -------- `zig build deps` ------------------------------------------
    // Builds only the self-contained third-party libraries for the selected
    // target. Useful in CI, and the one cross-target check that needs no
    // OpenSSL sysroot.
    const deps_step = b.step(
        "deps",
        "Build only the vendored third-party libraries for the selected target",
    );
    for (default_deps.boost.libs) |lib| deps_step.dependOn(&lib.step);
    if (default_deps.protobuf.lite) |lib| deps_step.dependOn(&lib.step);
    if (default_deps.catch2) |c2| {
        if (c2.lib) |lib| deps_step.dependOn(&lib.step);
    }

    // -------- `zig build all` -------------------------------------------
    // Every triple in the matrix, installed to zig-out/bin/<triple>/.
    const all_step = b.step("all", "Build every target in the cross-compilation matrix");
    var missing = std.ArrayList([]const u8).empty;
    for (targets.all) |entry| {
        const resolved = targets.resolve(b, entry);
        const built = addTarget(b, options, resolved, version_dir, generated, null) orelse
            continue;
        switch (built) {
            .no_openssl => |message| {
                missing.append(b.allocator, message) catch @panic("OOM");
                continue;
            },
            .built => |ok| {
                const dir = b.fmt("bin/{s}", .{entry.name});
                const install = b.addInstallArtifact(ok.exe, .{
                    .dest_dir = .{ .override = .{ .custom = dir } },
                });
                all_step.dependOn(&install.step);
                if (ok.test_exe) |t| {
                    const install_test = b.addInstallArtifact(t, .{
                        .dest_dir = .{ .override = .{ .custom = dir } },
                    });
                    all_step.dependOn(&install_test.step);
                }
            },
        }
    }
    if (missing.items.len > 0) {
        // Report every unsatisfied target at once: fixing them one build at a
        // time would mean eight round trips.
        var msg = std.ArrayList(u8).empty;
        msg.appendSlice(
            b.allocator,
            "zig build all cannot proceed: OpenSSL is missing for one or more targets.\n",
        ) catch @panic("OOM");
        for (missing.items) |m| {
            msg.appendSlice(b.allocator, "\n") catch @panic("OOM");
            msg.appendSlice(b.allocator, m) catch @panic("OOM");
            msg.appendSlice(b.allocator, "\n") catch @panic("OOM");
        }
        all_step.dependOn(&b.addFail(
            msg.toOwnedSlice(b.allocator) catch @panic("OOM"),
        ).step);
    }
}

const Built = struct {
    exe: *std.Build.Step.Compile,
    test_exe: ?*std.Build.Step.Compile,
};

const TargetResult = union(enum) {
    built: Built,
    no_openssl: []const u8,
};

/// The self-contained third-party libraries for one target. Unlike OpenSSL,
/// these are built by this build for every target, so they never fail to
/// resolve -- they only have to be fetched first.
const Deps = struct {
    boost: boost.Boost,
    protobuf: protobuf.Protobuf,
    /// Only present with -Dtests, mirroring fc_deps.json's
    /// `"when": "BUILD_TESTS"` gate on Catch2.
    catch2: ?catch2.Catch2,
};

/// Returns null when a lazy dependency still has to be fetched; the build
/// runner refetches and re-runs build() in that case.
fn addDeps(b: *std.Build, options: cfg.Options, target: std.Build.ResolvedTarget) ?Deps {
    return .{
        .boost = boost.add(b, options, target) orelse return null,
        .protobuf = protobuf.add(b, options, target) orelse return null,
        .catch2 = if (options.tests)
            (catch2.add(b, options, target) orelse return null)
        else
            null,
    };
}

/// Build localproxy (and localproxytest) for one target.
///
/// `prebuilt` reuses an already-created set of third-party libraries; pass null
/// to build them for this target.
fn addTarget(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
    version_dir: std.Build.LazyPath,
    generated: protobuf.Generated,
    prebuilt: ?Deps,
) ?TargetResult {
    // Resolved before anything is built: a target with no OpenSSL produces no
    // artifacts at all, so nothing half-linked can be emitted.
    const ssl = switch (openssl.resolve(b, options, target)) {
        .ok => |resolved| resolved,
        .missing => |message| return .{ .no_openssl = message },
    };
    const deps = prebuilt orelse (addDeps(b, options, target) orelse return null);

    const exe = b.addExecutable(.{
        .name = "localproxy",
        .root_module = appModule(
            b,
            options,
            target,
            version_dir,
            generated,
            deps,
            ssl,
            false,
        ),
    });

    var test_exe: ?*std.Build.Step.Compile = null;
    if (deps.catch2) |c2| {
        // CORE_SOURCES and UTIL_SOURCE are deliberately compiled a second time
        // here rather than shared through a static library: the test build
        // defines _AWSIOT_TUNNELING_NO_SSL, which swaps the websocket stream
        // from TLS to plain TCP. Sharing compiled objects between the two
        // executables would silently strip TLS from the production binary.
        // This mirrors the identical comment in CMakeLists.txt -- appModule is
        // called twice with different `is_test`, producing two independent
        // module graphs over the same source files.
        const mod = appModule(b, options, target, version_dir, generated, deps, ssl, true);
        c2.apply(mod);
        test_exe = b.addExecutable(.{ .name = "localproxytest", .root_module = mod });
    }

    return .{ .built = .{ .exe = exe, .test_exe = test_exe } };
}

/// Compiler flags for *our* translation units.
///
/// CMakeLists.txt appends this exact string via COMPILE_FLAGS regardless of
/// CMAKE_BUILD_TYPE, so -O2 is unconditional there and unconditional here.
fn appFlags(b: *std.Build, is_test: bool) []const []const u8 {
    var flags = std.ArrayList([]const u8).empty;
    flags.appendSlice(b.allocator, &.{
        // CMAKE_CXX_STANDARD 14 + CMAKE_CXX_EXTENSIONS OFF: plain c++14, not
        // gnu++14. Nothing else is implied -- notably not -pedantic.
        "-std=c++14",
        "-O2",
        "-D_FORTIFY_SOURCE=2",
        "-fPIE",
        "-fstack-protector-strong",
        "-Wall",
        "-Werror",
    }) catch @panic("OOM");
    if (is_test) flags.append(b.allocator, "-D_AWSIOT_TUNNELING_NO_SSL") catch @panic("OOM");
    return flags.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn appModule(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
    version_dir: std.Build.LazyPath,
    generated: protobuf.Generated,
    deps: Deps,
    ssl: openssl.Resolved,
    is_test: bool,
) *std.Build.Module {
    const mod = b.createModule(.{
        .target = target,
        .optimize = options.optimize,
        .link_libc = true,
        .link_libcpp = true,
        // Zig turns clang's UBSan on by default for C/C++ in Debug and
        // ReleaseSafe. The CMake build never enables it, and a trap on
        // undefined behavior is a runtime behavior difference rather than a
        // build-configuration one, so keep the two builds equivalent.
        .sanitize_c = .off,
    });

    // include_directories(${PROJECT_SOURCE_DIR}/src) and the generated
    // Version.h / Message.pb.h directories. These are ours, so they are plain
    // -I rather than -isystem.
    mod.addIncludePath(b.path("src"));
    mod.addIncludePath(version_dir);
    mod.addIncludePath(generated.dir);

    // Third-party headers as -isystem, so -Werror on our own code is never
    // tripped by Boost.Log's headers (see cmake/LocalproxyBoost.cmake, which
    // uses include_directories(SYSTEM ...) for the same reason).
    deps.boost.apply(mod);
    deps.protobuf.apply(mod);
    openssl.link(mod, ssl);

    // CMakeLists.txt derives TEST_COMPILER_FLAGS from CUSTOM_COMPILER_FLAGS
    // *before* appending this define, so the test binary deliberately does not
    // get it. Keep that asymmetry.
    if (options.no_ssl_host_verify_opt and !is_test)
        mod.addCMacro("_AWSIOT_TUNNELING_DISABLE_NO_SSL_HOST_VERIFY", "1");

    const flags = appFlags(b, is_test);
    var sources = std.ArrayList([]const u8).empty;
    sources.appendSlice(b.allocator, &core_sources) catch @panic("OOM");
    sources.appendSlice(b.allocator, &util_sources) catch @panic("OOM");
    if (is_test) {
        sources.appendSlice(b.allocator, &test_sources) catch @panic("OOM");
    } else {
        sources.append(b.allocator, main_source) catch @panic("OOM");
    }
    mod.addCSourceFiles(.{
        .root = b.path("."),
        .files = sources.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .flags = flags,
        .language = .cpp,
    });

    // CMake sets COMPILE_FLAGS as a target property, so ${PROTO_SRCS} is
    // compiled with the same flag set as the hand-written sources -- including
    // -Wall -Werror. Use `flags` here for that reason rather than relaxing them
    // for generated code.
    mod.addCSourceFile(.{
        .file = generated.source,
        .flags = flags,
        .language = .cpp,
    });

    if (target.result.os.tag == .windows) {
        mod.addCMacro("_WIN32_WINNT", options.win32_winnt);
        linkWindowsLibs(mod);
    }

    if (shouldLinkAtomic(options, target)) mod.linkSystemLibrary("atomic", .{});

    // find_package(Threads) / ${CMAKE_DL_LIBS}: on every POSIX target in the
    // matrix these live inside libc, which link_libc already provides. macOS
    // has no separate librt/libdl either.
    if (target.result.os.tag == .linux) {
        // Boost.Log's POSIX IPC backend calls shm_open/clock_gettime; glibc
        // splits those into librt (musl keeps them in libc, where Zig ships an
        // empty librt so naming it is harmless).
        mod.linkSystemLibrary("rt", .{});
    }

    return mod;
}

/// Windows socket and crypto libraries.
///
/// CMakeLists.txt never names these: an MSVC build gets them through the
/// #pragma comment(lib, ...) directives in Boost.Asio's and Boost.WinAPI's
/// headers. clang/MinGW does not honor those pragmas the same way, so the
/// libraries have to be requested explicitly or the link fails with undefined
/// WSA*/Bcrypt* symbols.
fn linkWindowsLibs(mod: *std.Build.Module) void {
    // ws2_32/mswsock: Winsock, used by Boost.Asio.
    mod.linkSystemLibrary("ws2_32", .{});
    mod.linkSystemLibrary("mswsock", .{});
    // bcrypt: Boost.Filesystem's unique_path random source (BCryptGenRandom).
    mod.linkSystemLibrary("bcrypt", .{});
    // crypt32: certificate store access reached through OpenSSL on Windows.
    mod.linkSystemLibrary("crypt32", .{});
    // advapi32/secur32: Boost.Log's Windows IPC and object-name support.
    mod.linkSystemLibrary("advapi32", .{});
    mod.linkSystemLibrary("secur32", .{});
}

/// lp_link_atomic() in cmake/LocalproxyUtil.cmake: never on macOS or MSVC,
/// off when LOCALPROXY_LINK_ATOMIC=OFF, otherwise probe.
///
/// The Zig equivalent of the probe is a static decision rather than a compile
/// test: Zig links its own compiler_rt, which supplies the out-of-line atomic
/// helpers on every target in the matrix, so nothing needs -latomic. `auto`
/// therefore resolves to off, and -Dlink-atomic=on remains available for a
/// toolchain that does need it.
fn shouldLinkAtomic(options: cfg.Options, target: std.Build.ResolvedTarget) bool {
    switch (target.result.os.tag) {
        .macos, .ios, .tvos, .watchos, .windows => return false,
        else => {},
    }
    return options.link_atomic == .on;
}

fn isHostTarget(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    const host = b.graph.host.result;
    const t = target.result;
    return t.cpu.arch == host.cpu.arch and t.os.tag == host.os.tag and t.abi == host.abi;
}

fn isHexLiteral(value: []const u8) bool {
    if (value.len < 3) return false;
    if (value[0] != '0') return false;
    if (value[1] != 'x' and value[1] != 'X') return false;
    for (value[2..]) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}
