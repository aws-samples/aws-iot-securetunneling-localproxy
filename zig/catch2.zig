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

pub const Catch2 = struct {
    lib: ?*std.Build.Step.Compile,
    include_dirs: []const std.Build.LazyPath,

    pub fn apply(self: Catch2, mod: *std.Build.Module) void {
        for (self.include_dirs) |dir| mod.addSystemIncludePath(dir);
        if (self.lib) |lib| mod.linkLibrary(lib) else {
            mod.linkSystemLibrary("Catch2Main", .{});
            mod.linkSystemLibrary("Catch2", .{});
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

fn systemCatch2Found(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    if (target.result.os.tag != b.graph.host.result.os.tag or
        target.result.cpu.arch != b.graph.host.result.cpu.arch) return false;
    const io = b.graph.io;
    for ([_][]const u8{ "/usr/include", "/usr/local/include", "/opt/homebrew/include" }) |prefix| {
        if (cfg.pathExists(io, b.pathJoin(&.{ prefix, "catch2", "catch_all.hpp" }))) return true;
    }
    return false;
}

pub fn add(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) ?Catch2 {
    const mode: cfg.DepMode = switch (options.resolveDep(options.catch2_source)) {
        .system => .system,
        .fetch => .fetch,
        .auto => if (systemCatch2Found(b, target)) .system else .fetch,
    };
    if (mode == .system) return .{ .lib = null, .include_dirs = &.{} };

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
