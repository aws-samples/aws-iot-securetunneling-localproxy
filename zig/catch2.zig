// Catch2 3.7.0 for the Zig build (test-only).
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The test sources include <catch2/catch_all.hpp>, so the real (non-amalgamated)
// Catch2 headers are required. Catch2 v3 also needs a generated
// catch2/catch_user_config.hpp; upstream produces it with configure_file over
// src/catch2/catch_user_config.hpp.in, and b.addConfigHeader in cmake style
// consumes the same template with the same (all-default) values, so Catch2's
// own compile-time feature detection decides everything as it does under CMake.
//
// Upstream splits the library in two -- Catch2 (everything except
// internal/catch_main.cpp) and Catch2WithMain (that one file). The repo links
// Catch2::Catch2WithMain, i.e. both, so a single static library containing all
// sources is the same thing with one fewer artifact.
//
// The dependency is lazy because fc_deps.json gates Catch2 on
// `"when": "BUILD_TESTS"`; nothing is downloaded unless -Dtests is passed.

const std = @import("std");
const cfg = @import("config.zig");
const system = @import("system.zig");
const targets = @import("targets.zig");

/// Version pinned by fc_deps.json.
pub const pinned_version = "3.7.0";

/// The major version the test sources require, and the same constraint
/// cmake/LocalproxyCatch2.cmake asserts with `find_package(Catch2 3 REQUIRED)`.
const required_major: u64 = 3;

const version_check = system.VersionCheck{
    .header = "catch2/catch_version_macros.hpp",
    .macro = "CATCH_VERSION_MAJOR",
    .minimum = required_major,
};

/// The two compiled libraries behind Catch2::Catch2WithMain. Order is link
/// order.
const system_lib_names = [_][]const u8{ "Catch2Main", "Catch2" };

pub const Catch2 = struct {
    lib: ?*std.Build.Step.Compile,
    include_dirs: []const std.Build.LazyPath,
    /// Where the pre-installed Catch2 was found; only set in `system` mode.
    prefix: ?system.Prefix = null,

    pub fn apply(self: Catch2, mod: *std.Build.Module) void {
        for (self.include_dirs) |dir| mod.addSystemIncludePath(dir);
        if (self.lib) |lib| mod.linkLibrary(lib) else {
            // The prefix the probe matched has to reach the command line:
            // detecting a Catch2 under /usr/local and then omitting -isystem/-L
            // for it would compile against whatever else is on the default
            // search path.
            if (self.prefix) |p| {
                p.applyInclude(mod);
                p.applyLib(mod);
            }
            for (system_lib_names) |name| mod.linkSystemLibrary(name, .{});
        }
    }
};

/// Every .cpp under src/catch2, discovered at configure time.
///
/// Upstream enumerates these explicitly in src/CMakeLists.txt. Walking the
/// directory is equivalent for a fixed pinned version -- src/catch2 contains
/// exactly the library sources, with tests living outside src/ -- and avoids a
/// 100-entry list that would have to be re-audited on every version bump.
fn sources(b: *std.Build, dep: *std.Build.Dependency) []const []const u8 {
    const io = b.graph.io;
    var files = std.ArrayList([]const u8).empty;

    const Walker = struct {
        fn walk(
            bb: *std.Build,
            root: std.Io.Dir,
            iod: std.Io,
            rel: []const u8,
            out: *std.ArrayList([]const u8),
        ) void {
            var dir = root.openDir(iod, rel, .{ .iterate = true }) catch |err|
                cfg.fatal("unable to enumerate Catch2 {s}: {s}", .{ rel, @errorName(err) });
            defer dir.close(iod);
            var it = dir.iterate();
            while (it.next(iod) catch null) |entry| {
                const name = bb.dupe(entry.name);
                const path = bb.fmt("{s}/{s}", .{ rel, name });
                switch (entry.kind) {
                    .directory => walk(bb, root, iod, path, out),
                    .file => if (std.mem.endsWith(u8, name, ".cpp"))
                        out.append(bb.allocator, path) catch @panic("OOM"),
                    else => {},
                }
            }
        }
    };
    Walker.walk(b, dep.builder.build_root.handle, io, "src/catch2", &files);

    if (files.items.len == 0) cfg.fatal("Catch2 src/catch2 contained no sources", .{});
    return files.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// Locate a pre-installed Catch2 that this build may actually link.
///
/// cmake/LocalproxyCatch2.cmake constrains the major version only --
/// `find_package(Catch2 3 REQUIRED)`, whose comment explains why ("Catch2 v2 and
/// v3 have incompatible headers and target names") -- so that is the constraint
/// mirrored here rather than the pinned 3.7.0 patch level. Both compiled
/// libraries behind Catch2::Catch2WithMain must be present, which is what makes
/// a headers-only install fall through to fetch instead of failing at link.
fn findSystemCatch2(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) ?system.Prefix {
    return system.find(b, options, target, version_check, &system_lib_names);
}

pub fn add(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) ?Catch2 {
    const requested = options.resolveDep(options.catch2_source);
    const found = if (requested == .fetch) null else findSystemCatch2(b, options, target);
    switch (requested) {
        // An explicit `system` that cannot be satisfied is a configuration
        // error, exactly as find_package(Catch2 3 REQUIRED) is in the CMake
        // build: it must not quietly fetch instead.
        .system => if (found == null) cfg.fatal(
            \\-Dcatch2-source=system (or -Ddep-mode=system) was requested, but no usable
            \\Catch2 v3 was found for target '{s}'.
            \\
            \\A usable installation needs headers reporting CATCH_VERSION_MAJOR {d} and both
            \\libCatch2 and libCatch2Main in the same library directory. Prefixes searched:
            \\-Ddep-prefix entries, then /usr, /usr/local, /opt/homebrew.
            \\
            \\Add one with -Ddep-prefix=<dir>[,<dir>...], or build Catch2 from the pinned
            \\sources with -Dcatch2-source=fetch.
        , .{ targets.nameOf(b, target), required_major }),
        .fetch, .auto => {},
    }
    if (found) |prefix| return .{ .lib = null, .include_dirs = &.{}, .prefix = prefix };

    const dep = b.lazyDependency("catch2", .{}) orelse return null;

    // All #cmakedefine entries stay undefined, which is what upstream's default
    // options produce; only the two substituted values are supplied.
    const user_config = b.addConfigHeader(.{
        .style = .{ .cmake = dep.path("src/catch2/catch_user_config.hpp.in") },
        .include_path = "catch2/catch_user_config.hpp",
    }, .{
        .CATCH_CONFIG_DEFAULT_REPORTER = @as([]const u8, "console"),
        .CATCH_CONFIG_CONSOLE_WIDTH = @as(i64, 80),
        // `#cmakedefine CATCH_CONFIG_FALLBACK_STRINGIFIER @...@` combines a
        // guard and a substitution on one line. CMake leaves it out entirely
        // when the option is unset; Zig needs the variable to exist, so name it
        // explicitly as undefined.
        .CATCH_CONFIG_FALLBACK_STRINGIFIER = @as(?[]const u8, null),
    });

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
    mod.addIncludePath(dep.path("src"));
    mod.addConfigHeader(user_config);
    mod.addCSourceFiles(.{
        .root = dep.path("."),
        .files = sources(b, dep),
        .flags = &cfg.third_party_flags,
        .language = .cpp,
    });

    // Consumers need both the source tree (for catch2/catch_all.hpp) and the
    // generated config header's directory. Allocated rather than a slice of a
    // temporary array literal, which would dangle past this function.
    const include_dirs = b.allocator.alloc(std.Build.LazyPath, 2) catch @panic("OOM");
    include_dirs[0] = dep.path("src");
    include_dirs[1] = user_config.getOutputDir();

    return .{
        .lib = b.addLibrary(.{
            .name = "Catch2WithMain",
            .root_module = mod,
            .linkage = .static,
        }),
        .include_dirs = include_dirs,
    };
}
