// Cross-compilation target matrix for the Zig build.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The CMake build has no equivalent of this list: it builds whatever the
// active toolchain/sysroot targets. Zig ships its own C/C++ toolchain for
// every triple below, so the matrix can be enumerated up front and driven
// from one host.

const std = @import("std");

pub const Entry = struct {
    /// Stable name used for `zig-out/bin/<name>/` and for looking up a
    /// per-target OpenSSL under `-Dopenssl-sysroots=<dir>/<name>`.
    name: []const u8,
    /// `arch-os-abi` as understood by `std.Target.Query.parse`.
    arch_os_abi: []const u8,
    /// `-mcpu`-style feature string, or null for the target default.
    cpu_features: ?[]const u8 = null,
};

/// Every triple `zig build all` walks.
///
/// The glibc versions are pinned deliberately: without a suffix Zig defaults
/// to a recent glibc, which would produce binaries that refuse to start on
/// older distributions. 2.17 (RHEL 7 era) matches the oldest platform the
/// released Linux artifacts support.
pub const all = [_]Entry{
    .{ .name = "x86_64-linux-gnu", .arch_os_abi = "x86_64-linux-gnu.2.17" },
    .{ .name = "x86_64-linux-musl", .arch_os_abi = "x86_64-linux-musl" },
    .{ .name = "aarch64-linux-gnu", .arch_os_abi = "aarch64-linux-gnu.2.17" },
    .{ .name = "aarch64-linux-musl", .arch_os_abi = "aarch64-linux-musl" },
    // 32-bit ARM: the `hf` ABI already implies hard float, but Zig's default
    // CPU model for `arm-linux` is conservative. Naming v7-A + VFPv3-D16
    // matches what the released armv7l artifacts are built for, and is also
    // what Boost.Context's `.S` sources require should a transitive dependency
    // ever pull them in (Boost.Context is not compiled today -- see
    // zig/boost.zig -- but the flag costs nothing and removes the trap).
    .{
        .name = "arm-linux-gnueabihf",
        .arch_os_abi = "arm-linux-gnueabihf",
        .cpu_features = "generic+v7a+vfp3d16",
    },
    .{
        .name = "arm-linux-musleabihf",
        .arch_os_abi = "arm-linux-musleabihf",
        .cpu_features = "generic+v7a+vfp3d16",
    },
    .{ .name = "aarch64-macos", .arch_os_abi = "aarch64-macos" },
    // 32-bit MinGW. Windows socket libraries have to be named explicitly here;
    // see the comment in build.zig.
    .{ .name = "x86-windows-gnu", .arch_os_abi = "x86-windows-gnu" },
};

/// Resolve one matrix entry into a `ResolvedTarget`.
pub fn resolve(b: *std.Build, entry: Entry) std.Build.ResolvedTarget {
    const query = std.Target.Query.parse(.{
        .arch_os_abi = entry.arch_os_abi,
        .cpu_features = entry.cpu_features orelse "baseline",
    }) catch |err| std.debug.panic(
        "invalid target query '{s}' for matrix entry '{s}': {s}",
        .{ entry.arch_os_abi, entry.name, @errorName(err) },
    );
    return b.resolveTargetQuery(query);
}

/// Re-resolve `base` with extra x86 CPU features enabled.
///
/// Boost.Atomic and Boost.Log each ship a couple of translation units that use
/// SSSE3/SSE4.1/AVX2 intrinsics and are selected at run time by a cpuid
/// dispatch. Upstream compiles them with per-source `-mssse3`/`-msse4.1`/
/// `-mavx2`. Passing those as plain compiler flags is not enough under Zig: the
/// module's resolved target still advertises the baseline feature set, and
/// clang then refuses to inline the always_inline intrinsics ("requires target
/// feature 'sse4.1', but would be inlined into a function compiled without
/// support for 'sse4.1'"). Enabling the feature on the target for just those
/// modules is the equivalent that Zig does understand.
pub fn withX86Features(
    b: *std.Build,
    base: std.Build.ResolvedTarget,
    features: []const std.Target.x86.Feature,
) std.Build.ResolvedTarget {
    var query = base.query;
    for (features) |feature| query.cpu_features_add.addFeature(@intFromEnum(feature));
    return b.resolveTargetQuery(query);
}

/// Human-readable name for an arbitrary resolved target, used in diagnostics
/// and as the per-target OpenSSL sysroot directory name.
pub fn nameOf(b: *std.Build, target: std.Build.ResolvedTarget) []const u8 {
    const t = target.result;
    // Match the matrix names so that `-Dtarget=...` and `zig build all` look
    // for the same sysroot directory.
    for (all) |entry| {
        const resolved = resolve(b, entry);
        if (resolved.result.cpu.arch == t.cpu.arch and
            resolved.result.os.tag == t.os.tag and
            resolved.result.abi == t.abi) return entry.name;
    }
    return b.fmt("{s}-{s}-{s}", .{
        @tagName(t.cpu.arch),
        @tagName(t.os.tag),
        @tagName(t.abi),
    });
}
