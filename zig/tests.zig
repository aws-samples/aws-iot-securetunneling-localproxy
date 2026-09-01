// Unit tests for the Zig build's own decision logic (`zig build test-build`).
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// These cover the pure predicates the dependency probes rest on, which are the
// parts that decide -- silently, at configure time -- whether a pre-installed
// library may be linked into the selected target and which library directory is
// used. A wrong answer there produces a plausible-looking but ABI-corrupt
// binary, so it is worth pinning down without a full build.
//
// `zig build test` remains the project's Catch2 suite; this step is separate.

const std = @import("std");
const system = @import("system.zig");

fn parse(spec: []const u8) std.Target {
    const query = std.Target.Query.parse(.{ .arch_os_abi = spec }) catch unreachable;
    return std.zig.system.resolveTargetQuery(std.testing.io, query) catch unreachable;
}

test "hostMatches rejects a differing ABI" {
    // The defect this guards: on a glibc host, x86_64-linux-musl compared only
    // on os+arch looks native, and glibc archives get linked into a musl binary.
    const host = parse("x86_64-linux-gnu.2.35");
    try std.testing.expect(!system.hostMatches(parse("x86_64-linux-musl"), host));
    try std.testing.expect(system.hostMatches(parse("x86_64-linux-gnu.2.35"), host));
}

test "hostMatches rejects a differing glibc floor" {
    // -Dtarget=x86_64-linux-gnu.2.17 asks for a binary that runs on glibc 2.17;
    // the host's own libraries reference its newer symbol versions.
    const host = parse("x86_64-linux-gnu.2.35");
    try std.testing.expect(!system.hostMatches(parse("x86_64-linux-gnu.2.17"), host));
    try std.testing.expect(!system.hostMatches(parse("x86_64-linux-gnu.2.31"), host));
}

test "hostMatches rejects a differing architecture" {
    const host = parse("x86_64-linux-gnu.2.35");
    try std.testing.expect(!system.hostMatches(parse("aarch64-linux-gnu.2.35"), host));
}

test "hostMatches ignores the glibc floor where there is none" {
    const host = parse("aarch64-macos");
    try std.testing.expect(system.hostMatches(parse("aarch64-macos"), host));
    try std.testing.expect(!system.hostMatches(parse("x86_64-macos"), host));
}

test "libDirs puts the multiarch directory ahead of the bare lib" {
    // The defect this guards: /usr/lib exists on every Linux distribution, so a
    // bare `lib` tried first always matches and /usr/lib/x86_64-linux-gnu --
    // where Debian and Ubuntu keep libssl -- is never reached.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const dirs = system.libDirsAlloc(arena.allocator(), "/usr", parse("x86_64-linux-gnu.2.35"));
    try std.testing.expectEqual(@as(usize, 3), dirs.len);
    try std.testing.expectEqualStrings("/usr/lib/x86_64-linux-gnu", dirs[0]);
    try std.testing.expectEqualStrings("/usr/lib64", dirs[1]);
    try std.testing.expectEqualStrings("/usr/lib", dirs[2]);
}

test "libDirs omits a multiarch directory where the convention does not apply" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const dirs = system.libDirsAlloc(arena.allocator(), "/opt/ssl", parse("aarch64-macos"));
    try std.testing.expectEqual(@as(usize, 2), dirs.len);
    try std.testing.expectEqualStrings("/opt/ssl/lib64", dirs[0]);
    try std.testing.expectEqualStrings("/opt/ssl/lib", dirs[1]);
}

test "multiarchTuple follows the ARM ABI" {
    try std.testing.expectEqualStrings(
        "arm-linux-gnueabihf",
        system.multiarchTuple(parse("arm-linux-gnueabihf")).?,
    );
    try std.testing.expectEqualStrings(
        "arm-linux-musleabihf",
        system.multiarchTuple(parse("arm-linux-musleabihf")).?,
    );
    try std.testing.expectEqualStrings(
        "x86_64-linux-musl",
        system.multiarchTuple(parse("x86_64-linux-musl")).?,
    );
}

test "readVersionMacro parses a #define and tolerates near-misses" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "version.hpp", .data =
        \\// comment mentioning BOOST_VERSION 999999
        \\#define BOOST_VERSION_HPP
        \\#  define BOOST_VERSION 108700
        \\#define BOOST_LIB_VERSION "1_87"
        \\
    });

    const path = try tmp.dir.realPathFileAlloc(io, "version.hpp", std.testing.allocator);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqual(
        @as(?u64, 108700),
        system.readVersionMacroAt(io, std.testing.allocator, path, "BOOST_VERSION"),
    );
    // A string-valued macro is not a version number and must not parse.
    try std.testing.expectEqual(
        @as(?u64, null),
        system.readVersionMacroAt(io, std.testing.allocator, path, "BOOST_LIB_VERSION"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        system.readVersionMacroAt(io, std.testing.allocator, path, "NOT_DEFINED"),
    );
}
