// Boost 1.87.0 for the Zig build.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// `fetch` mode compiles the pinned Boost tarball (the same URL and version as
// fc_deps.json) directly, one Zig static library per Boost library, mirroring
// each library's own libs/<lib>/CMakeLists.txt: the same source lists, the
// same platform source selection, and the same public/private compile
// definitions. We deliberately do *not* run Boost's CMake -- the point of the
// Zig build is that one host toolchain covers every target in
// zig/targets.zig, and shelling out to another build system per target would
// give that up.
//
// Source selection notes, all taken from upstream's CMakeLists:
//   * Boost.System and Boost.Regex are INTERFACE (header-only) in 1.87; there
//     is nothing to compile even though CMake names them as components.
//   * Boost.Thread selects pthread/* or win32/* by platform.
//   * Boost.Atomic and Boost.Log have x86-only SIMD translation units that
//     need their own -m flags.
//   * Boost.Container and Boost.Atomic are not localproxy dependencies
//     directly; they are compiled because Boost.Thread, Boost.Log and
//     Boost.Filesystem link them (the CMake fetch path resolves these
//     transitives automatically).
//
// `system` mode links a pre-installed static Boost instead, matching
// cmake/LocalproxyBoost.cmake's system branch.

const std = @import("std");
const cfg = @import("config.zig");
const targets = @import("targets.zig");

/// Compiled components requested by CMakeLists.txt, plus the transitives that
/// Boost's own CMake would have pulled in. Order is link order.
const system_lib_names = [_][]const u8{
    "boost_log_setup",
    "boost_log",
    "boost_program_options",
    "boost_filesystem",
    "boost_thread",
    "boost_chrono",
    "boost_date_time",
    "boost_atomic",
    "boost_container",
};

/// Public compile definitions every consumer of a static Boost needs.
const public_defines = [_][2][]const u8{
    // Boost headers otherwise emit #pragma comment(lib, ...) naming b2-style
    // decorated import libraries that this build never produces. The CMake
    // fetch path sets the same thing for MSVC; setting it unconditionally is
    // harmless on ELF/Mach-O and keeps the two builds aligned.
    .{ "BOOST_ALL_NO_LIB", "1" },
    .{ "BOOST_CHRONO_STATIC_LINK", "1" },
    .{ "BOOST_CONTAINER_STATIC_LINK", "1" },
    .{ "BOOST_DATE_TIME_STATIC_LINK", "1" },
    .{ "BOOST_FILESYSTEM_STATIC_LINK", "1" },
    .{ "BOOST_LOG_STATIC_LINK", "1" },
    .{ "BOOST_PROGRAM_OPTIONS_STATIC_LINK", "1" },
    .{ "BOOST_THREAD_STATIC_LINK", "1" },
};

pub const Boost = struct {
    mode: cfg.DepMode,
    libs: []const *std.Build.Step.Compile,
    /// Every libs/<lib>/include directory, for -isystem on consumers.
    include_dirs: []const std.Build.LazyPath,

    /// Put Boost on a consuming module: headers as system includes so that our
    /// own -Wall -Werror translation units are not held responsible for
    /// Boost.Log's headers (the same reason cmake/LocalproxyBoost.cmake uses
    /// include_directories(SYSTEM ...)).
    pub fn apply(self: Boost, mod: *std.Build.Module) void {
        for (self.include_dirs) |dir| mod.addSystemIncludePath(dir);
        for (public_defines) |d| mod.addCMacro(d[0], d[1]);
        switch (self.mode) {
            .fetch, .auto => for (self.libs) |lib| mod.linkLibrary(lib),
            .system => for (system_lib_names) |name| mod.linkSystemLibrary(name, .{}),
        }
    }
};

/// Enumerate the modular superproject's include directories.
///
/// Boost 1.87's -cmake tarball is the modular layout: headers live under
/// libs/<lib>/include. `libs/numeric` is the one aggregate that has no
/// include/ of its own and instead nests conversion/, interval/, odeint/ and
/// ublas/; recursing exactly one level for that case picks those up without
/// dragging in unrelated trees such as libs/mpl/preprocessed/include.
fn includeDirs(b: *std.Build, dep: *std.Build.Dependency) []const std.Build.LazyPath {
    const io = b.graph.io;
    var dirs = std.ArrayList(std.Build.LazyPath).empty;

    var libs = dep.builder.build_root.handle.openDir(io, "libs", .{ .iterate = true }) catch |err|
        cfg.fatal("unable to enumerate Boost libs/: {s}", .{@errorName(err)});
    defer libs.close(io);

    var it = libs.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        const name = b.dupe(entry.name);
        const direct = b.fmt("libs/{s}/include", .{name});
        if (cfg.pathExists(io, dep.builder.pathFromRoot(direct))) {
            dirs.append(b.allocator, dep.path(direct)) catch @panic("OOM");
            continue;
        }
        // Aggregate directory (libs/numeric): one level deeper.
        var nested = libs.openDir(io, name, .{ .iterate = true }) catch continue;
        defer nested.close(io);
        var nit = nested.iterate();
        while (nit.next(io) catch null) |sub| {
            if (sub.kind != .directory) continue;
            const path = b.fmt("libs/{s}/{s}/include", .{ name, b.dupe(sub.name) });
            if (cfg.pathExists(io, dep.builder.pathFromRoot(path)))
                dirs.append(b.allocator, dep.path(path)) catch @panic("OOM");
        }
    }

    if (dirs.items.len == 0) cfg.fatal("Boost libs/ contained no include directories", .{});
    return dirs.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// Is `target` a glibc target whose declared glibc floor is below major.minor?
/// Returns false for musl, Windows and macOS, which have no glibc floor.
fn glibcOlderThan(target: std.Target, major: u32, minor: u32) bool {
    if (target.os.tag != .linux or !target.abi.isGnu()) return false;
    const glibc = target.os.version_range.linux.glibc;
    return glibc.order(.{ .major = major, .minor = minor, .patch = 0 }) == .lt;
}

const LibSpec = struct {
    name: []const u8,
    /// Paths relative to libs/<dir>/.
    files: []const []const u8,
    dir: []const u8,
    /// PRIVATE compile definitions from the library's own CMakeLists.
    private_defines: []const [2][]const u8 = &.{},
    /// Extra PRIVATE include directories (e.g. Boost.Log's src/).
    private_includes: []const []const u8 = &.{},
    /// x86 CPU features this translation unit needs; see
    /// targets.withX86Features for why these are target features rather than
    /// plain -m flags.
    x86_features: []const std.Target.x86.Feature = &.{},
};

fn addLib(
    b: *std.Build,
    dep: *std.Build.Dependency,
    options: cfg.Options,
    base_target: std.Build.ResolvedTarget,
    include_dirs: []const std.Build.LazyPath,
    spec: LibSpec,
) *std.Build.Step.Compile {
    const target = if (spec.x86_features.len == 0)
        base_target
    else
        targets.withX86Features(b, base_target, spec.x86_features);
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
    for (include_dirs) |dir| mod.addSystemIncludePath(dir);
    for (spec.private_includes) |sub|
        mod.addIncludePath(dep.path(b.fmt("libs/{s}/{s}", .{ spec.dir, sub })));
    for (public_defines) |d| mod.addCMacro(d[0], d[1]);
    for (spec.private_defines) |d| mod.addCMacro(d[0], d[1]);

    var flags = std.ArrayList([]const u8).empty;
    flags.appendSlice(b.allocator, &cfg.third_party_flags) catch @panic("OOM");

    // Split C from C++: Boost.Container ships one .c file (alloc_lib.c) that
    // must not be fed -std=c++14.
    var cxx = std.ArrayList([]const u8).empty;
    var c = std.ArrayList([]const u8).empty;
    for (spec.files) |f| {
        if (std.mem.endsWith(u8, f, ".c"))
            c.append(b.allocator, f) catch @panic("OOM")
        else
            cxx.append(b.allocator, f) catch @panic("OOM");
    }

    const root = dep.path(b.fmt("libs/{s}", .{spec.dir}));
    if (cxx.items.len > 0) mod.addCSourceFiles(.{
        .root = root,
        .files = cxx.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .flags = flags.items,
        .language = .cpp,
    });
    if (c.items.len > 0) mod.addCSourceFiles(.{
        .root = root,
        .files = c.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .flags = &.{"-w"},
        .language = .c,
    });

    return b.addLibrary(.{
        .name = spec.name,
        .root_module = mod,
        .linkage = .static,
    });
}

/// Standard prefixes probed in `auto` mode, standing in for
/// find_package(Boost). Only consulted for a native build: a cross target must
/// not be handed the host's headers.
fn systemBoostFound(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    if (target.result.os.tag != b.graph.host.result.os.tag or
        target.result.cpu.arch != b.graph.host.result.cpu.arch) return false;
    const io = b.graph.io;
    for ([_][]const u8{ "/usr/include", "/usr/local/include", "/opt/homebrew/include" }) |prefix| {
        if (cfg.pathExists(io, b.pathJoin(&.{ prefix, "boost", "version.hpp" }))) return true;
    }
    return false;
}

/// Build (or resolve) Boost for `target`.
///
/// Returns null when the lazy dependency has not been fetched yet; the Zig
/// build runner refetches and re-runs build() in that case.
pub fn add(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) ?Boost {
    // `auto` probes for a pre-installed Boost and only builds from source when
    // it is missing, matching LOCALPROXY_DEP_MODE=auto.
    const mode: cfg.DepMode = switch (options.resolveDep(options.boost_source)) {
        .system => .system,
        .fetch => .fetch,
        .auto => if (systemBoostFound(b, target)) .system else .fetch,
    };
    if (mode == .system) return .{ .mode = .system, .libs = &.{}, .include_dirs = &.{} };

    const dep = b.lazyDependency("boost", .{}) orelse return null;
    const include_dirs = includeDirs(b, dep);
    const t = target.result;
    const is_windows = t.os.tag == .windows;
    const is_x86 = t.cpu.arch == .x86 or t.cpu.arch == .x86_64;

    var libs = std.ArrayList(*std.Build.Step.Compile).empty;

    // --- Boost.Atomic --------------------------------------------------
    {
        var files = std.ArrayList([]const u8).empty;
        files.append(b.allocator, "src/lock_pool.cpp") catch @panic("OOM");
        if (is_windows) files.append(b.allocator, "src/wait_on_address.cpp") catch @panic("OOM");
        libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
            .name = "boost_atomic",
            .dir = "atomic",
            .files = files.toOwnedSlice(b.allocator) catch @panic("OOM"),
            .private_includes = &.{"src"},
        })) catch @panic("OOM");

        // The two SIMD translation units are x86-only and each needs its own
        // -m flags, exactly as upstream's set_source_files_properties does.
        if (is_x86) {
            libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
                .name = "boost_atomic_sse2",
                .dir = "atomic",
                .files = &.{"src/find_address_sse2.cpp"},
                .private_includes = &.{"src"},
                .x86_features = &.{ .sse, .sse2 },
            })) catch @panic("OOM");
            libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
                .name = "boost_atomic_sse41",
                .dir = "atomic",
                .files = &.{"src/find_address_sse41.cpp"},
                .private_includes = &.{"src"},
                .x86_features = &.{ .sse, .sse2, .sse3, .ssse3, .sse4_1 },
            })) catch @panic("OOM");
        }
    }

    // --- Boost.Container ------------------------------------------------
    libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
        .name = "boost_container",
        .dir = "container",
        .files = &.{
            "src/alloc_lib.c",
            "src/dlmalloc.cpp",
            "src/global_resource.cpp",
            "src/monotonic_buffer_resource.cpp",
            "src/pool_resource.cpp",
            "src/synchronized_pool_resource.cpp",
            "src/unsynchronized_pool_resource.cpp",
        },
    })) catch @panic("OOM");

    // --- Boost.Chrono ---------------------------------------------------
    libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
        .name = "boost_chrono",
        .dir = "chrono",
        .files = &.{
            "src/chrono.cpp",
            "src/process_cpu_clocks.cpp",
            "src/thread_clock.cpp",
        },
        .private_defines = &.{.{ "BOOST_CHRONO_SOURCE", "1" }},
    })) catch @panic("OOM");

    // --- Boost.DateTime -------------------------------------------------
    libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
        .name = "boost_date_time",
        .dir = "date_time",
        .files = &.{"src/gregorian/greg_month.cpp"},
        .private_defines = &.{.{ "BOOST_DATE_TIME_SOURCE", "1" }},
    })) catch @panic("OOM");

    // --- Boost.Filesystem -----------------------------------------------
    {
        var files = std.ArrayList([]const u8).empty;
        files.appendSlice(b.allocator, &.{
            "src/codecvt_error_category.cpp",
            "src/exception.cpp",
            "src/operations.cpp",
            "src/directory.cpp",
            "src/path.cpp",
            "src/path_traits.cpp",
            "src/portability.cpp",
            "src/unique_path.cpp",
            "src/utf8_codecvt_facet.cpp",
        }) catch @panic("OOM");
        if (is_windows)
            files.append(b.allocator, "src/windows_file_codecvt.cpp") catch @panic("OOM");

        var defines = std.ArrayList([2][]const u8).empty;
        defines.append(b.allocator, .{ "BOOST_FILESYSTEM_SOURCE", "1" }) catch @panic("OOM");
        // C++14 has no std::atomic_ref, so upstream's
        // BOOST_FILESYSTEM_HAS_CXX20_ATOMIC_REF probe would fail; declaring
        // that up front is what makes Boost.Filesystem fall back to
        // Boost.Atomic (already built above).
        defines.append(b.allocator, .{ "BOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF", "1" }) catch
            @panic("OOM");
        if (is_windows) {
            defines.appendSlice(b.allocator, &.{
                .{ "BOOST_USE_WINDOWS_H", "1" },
                .{ "WIN32_LEAN_AND_MEAN", "1" },
                .{ "NOMINMAX", "1" },
                .{ "_WIN32_WINNT", options.win32_winnt },
                // Upstream prefers BCrypt and falls back to WinCrypt when the
                // has_bcrypt probe fails. bcrypt is available on the
                // _WIN32_WINNT levels this build targets and MinGW ships the
                // import library, so take the BCrypt path.
                .{ "BOOST_FILESYSTEM_HAS_BCRYPT", "1" },
                .{ "_CRT_SECURE_NO_WARNINGS", "1" },
                .{ "_SCL_SECURE_NO_WARNINGS", "1" },
            }) catch @panic("OOM");
        }
        // Upstream discovers these with check_cxx_source_compiles. Zig has no
        // configure-time compile probe, and every one of them only enables a
        // faster path (statx, sendfile, dirent d_type, ...); leaving them unset
        // selects the portable fallbacks. See docs/ZIG_BUILD.md.
        //
        // getrandom is the one that has to be decided rather than defaulted.
        // unique_path.cpp keys off `__has_include(<sys/random.h>)`, and Zig
        // ships a single (recent) set of glibc headers in which that header
        // always exists but only declares getrandom() for glibc >= 2.25. On a
        // real glibc 2.17 sysroot the header would be absent and Boost would
        // pick its /dev/urandom fallback; DISABLE_GETRANDOM (an upstream
        // option) selects that same fallback here.
        if (glibcOlderThan(t, 2, 25))
            defines.append(b.allocator, .{ "BOOST_FILESYSTEM_DISABLE_GETRANDOM", "1" }) catch
                @panic("OOM");

        libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
            .name = "boost_filesystem",
            .dir = "filesystem",
            .files = files.toOwnedSlice(b.allocator) catch @panic("OOM"),
            .private_defines = defines.toOwnedSlice(b.allocator) catch @panic("OOM"),
            .private_includes = &.{"src"},
        })) catch @panic("OOM");
    }

    // --- Boost.Thread ---------------------------------------------------
    {
        const files: []const []const u8 = if (is_windows) &.{
            "src/win32/thread.cpp",
            "src/win32/tss_dll.cpp",
            "src/win32/tss_pe.cpp",
            "src/win32/thread_primitives.cpp",
            "src/future.cpp",
        } else &.{
            "src/pthread/thread.cpp",
            "src/pthread/once.cpp",
            "src/future.cpp",
        };
        libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
            .name = "boost_thread",
            .dir = "thread",
            .files = files,
            .private_defines = &.{
                .{ "BOOST_THREAD_SOURCE", "1" },
                .{ "BOOST_THREAD_BUILD_LIB", "1" },
            },
        })) catch @panic("OOM");
    }

    // --- Boost.ProgramOptions -------------------------------------------
    libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
        .name = "boost_program_options",
        .dir = "program_options",
        .files = &.{
            "src/cmdline.cpp",
            "src/config_file.cpp",
            "src/convert.cpp",
            "src/options_description.cpp",
            "src/parsers.cpp",
            "src/positional_options.cpp",
            "src/split.cpp",
            "src/utf8_codecvt_facet.cpp",
            "src/value_semantic.cpp",
            "src/variables_map.cpp",
            "src/winmain.cpp",
        },
        .private_defines = &.{.{ "BOOST_PROGRAM_OPTIONS_SOURCE", "1" }},
    })) catch @panic("OOM");

    // --- Boost.Log and Boost.Log.Setup ----------------------------------
    {
        var common = std.ArrayList([2][]const u8).empty;
        common.appendSlice(b.allocator, &.{
            .{ "__STDC_CONSTANT_MACROS", "1" },
            .{ "BOOST_SPIRIT_USE_PHOENIX_V3", "1" },
            // Keep Boost.Log from taking a dependency on Boost.Chrono, as
            // upstream does.
            .{ "BOOST_THREAD_DONT_USE_CHRONO", "1" },
            // Boost.Regex is upstream's default regex backend and is
            // header-only in 1.87, so nothing extra has to be compiled.
            .{ "BOOST_LOG_USE_BOOST_REGEX", "1" },
        }) catch @panic("OOM");

        var files = std.ArrayList([]const u8).empty;
        files.appendSlice(b.allocator, &.{
            "src/attribute_name.cpp",
            "src/attribute_set.cpp",
            "src/attribute_value_set.cpp",
            "src/code_conversion.cpp",
            "src/core.cpp",
            "src/record_ostream.cpp",
            "src/severity_level.cpp",
            "src/global_logger_storage.cpp",
            "src/named_scope.cpp",
            "src/process_name.cpp",
            "src/process_id.cpp",
            "src/thread_id.cpp",
            "src/timer.cpp",
            "src/exceptions.cpp",
            "src/default_attribute_names.cpp",
            "src/default_sink.cpp",
            "src/text_ostream_backend.cpp",
            "src/text_file_backend.cpp",
            "src/text_multifile_backend.cpp",
            "src/thread_specific.cpp",
            "src/once_block.cpp",
            "src/timestamp.cpp",
            "src/threadsafe_queue.cpp",
            "src/event.cpp",
            "src/trivial.cpp",
            "src/spirit_encoding.cpp",
            "src/format_parser.cpp",
            "src/date_time_format_parser.cpp",
            "src/named_scope_format_parser.cpp",
            "src/permissions.cpp",
            "src/dump.cpp",
        }) catch @panic("OOM");

        if (is_windows) {
            files.appendSlice(b.allocator, &.{
                "src/windows/light_rw_mutex.cpp",
                "src/windows/is_debugger_present.cpp",
                "src/windows/debug_output_backend.cpp",
                "src/windows/object_name.cpp",
                "src/windows/mapped_shared_memory.cpp",
                "src/windows/ipc_sync_wrappers.cpp",
                "src/windows/ipc_reliable_message_queue.cpp",
            }) catch @panic("OOM");
            common.appendSlice(b.allocator, &.{
                .{ "BOOST_USE_WINDOWS_H", "1" },
                .{ "WIN32_LEAN_AND_MEAN", "1" },
                .{ "NOMINMAX", "1" },
                .{ "SECURITY_WIN32", "1" },
                .{ "_WIN32_WINNT", options.win32_winnt },
                .{ "_CRT_SECURE_NO_WARNINGS", "1" },
                .{ "_SCL_SECURE_NO_WARNINGS", "1" },
                // The Windows event log backend needs simple_event_log.h/.rc
                // produced by the message compiler (windmc/mc.exe), which is
                // not part of the Zig toolchain. Upstream's CMakeLists takes
                // exactly this branch when it cannot find a message compiler,
                // so this is upstream behavior rather than a local shortcut.
                .{ "BOOST_LOG_WITHOUT_EVENT_LOG", "1" },
            }) catch @panic("OOM");
            // The syslog backend is POSIX-only in upstream's Windows branch.
            common.append(b.allocator, .{ "BOOST_LOG_WITHOUT_SYSLOG", "1" }) catch @panic("OOM");
        } else {
            files.appendSlice(b.allocator, &.{
                "src/syslog_backend.cpp",
                "src/posix/object_name.cpp",
                "src/posix/ipc_reliable_message_queue.cpp",
            }) catch @panic("OOM");
            // <syslog.h> is present on every POSIX target in the matrix, which
            // is what upstream's native-syslog probe establishes.
            common.append(b.allocator, .{ "BOOST_LOG_USE_NATIVE_SYSLOG", "1" }) catch @panic("OOM");
            if (t.os.tag == .linux)
                common.append(b.allocator, .{ "_XOPEN_SOURCE", "600" }) catch @panic("OOM");
        }

        var log_defines = std.ArrayList([2][]const u8).empty;
        log_defines.appendSlice(b.allocator, common.items) catch @panic("OOM");
        log_defines.append(b.allocator, .{ "BOOST_LOG_BUILDING_THE_LIB", "1" }) catch @panic("OOM");
        if (is_x86) {
            log_defines.appendSlice(b.allocator, &.{
                .{ "BOOST_LOG_USE_SSSE3", "1" },
                .{ "BOOST_LOG_USE_AVX2", "1" },
            }) catch @panic("OOM");
        }

        libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
            .name = "boost_log",
            .dir = "log",
            .files = files.toOwnedSlice(b.allocator) catch @panic("OOM"),
            .private_defines = log_defines.items,
            .private_includes = &.{"src"},
        })) catch @panic("OOM");

        if (is_x86) {
            // dump_ssse3.cpp / dump_avx2.cpp are dispatched at runtime by
            // dump.cpp and must be compiled with the matching ISA flags.
            // Upstream also passes -fabi-version=0 for GCC; clang does not
            // need (or accept) it.
            libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
                .name = "boost_log_ssse3",
                .dir = "log",
                .files = &.{"src/dump_ssse3.cpp"},
                .private_defines = log_defines.items,
                .private_includes = &.{"src"},
                .x86_features = &.{ .sse, .sse2, .sse3, .ssse3 },
            })) catch @panic("OOM");
            libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
                .name = "boost_log_avx2",
                .dir = "log",
                .files = &.{"src/dump_avx2.cpp"},
                .private_defines = log_defines.items,
                .private_includes = &.{"src"},
                .x86_features = &.{ .avx, .avx2 },
            })) catch @panic("OOM");
        }

        var setup_defines = std.ArrayList([2][]const u8).empty;
        setup_defines.appendSlice(b.allocator, common.items) catch @panic("OOM");
        setup_defines.append(b.allocator, .{ "BOOST_LOG_SETUP_BUILDING_THE_LIB", "1" }) catch
            @panic("OOM");

        libs.append(b.allocator, addLib(b, dep, options, target, include_dirs, .{
            .name = "boost_log_setup",
            .dir = "log",
            .files = &.{
                "src/setup/parser_utils.cpp",
                "src/setup/init_from_stream.cpp",
                "src/setup/init_from_settings.cpp",
                "src/setup/settings_parser.cpp",
                "src/setup/filter_parser.cpp",
                "src/setup/formatter_parser.cpp",
                "src/setup/default_filter_factory.cpp",
                "src/setup/matches_relation_factory.cpp",
                "src/setup/default_formatter_factory.cpp",
            },
            .private_defines = setup_defines.items,
            .private_includes = &.{"src"},
        })) catch @panic("OOM");
    }

    return .{
        .mode = mode,
        .libs = libs.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .include_dirs = include_dirs,
    };
}
