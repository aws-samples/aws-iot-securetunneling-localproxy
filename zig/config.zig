// Build options and small helpers shared by the zig/ build modules.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// Mirrors LOCALPROXY_DEP_MODE.
pub const DepMode = enum { auto, system, fetch };

/// Mirrors the per-dependency LOCALPROXY_<DEP>_SOURCE overrides, where an
/// empty CMake value means "inherit LOCALPROXY_DEP_MODE".
pub const DepSource = enum { inherit, system, fetch };

/// Mirrors LOCALPROXY_LINK_ATOMIC.
pub const LinkAtomic = enum { auto, on, off };

pub const Options = struct {
    tests: bool,
    openssl_static: bool,
    release: bool,
    no_ssl_host_verify_opt: bool,
    dep_mode: DepMode,
    boost_source: DepSource,
    protobuf_source: DepSource,
    catch2_source: DepSource,
    link_atomic: LinkAtomic,
    protoc: ?[]const u8,
    win32_winnt: []const u8,
    openssl_include: ?[]const u8,
    openssl_libdir: ?[]const u8,
    openssl_sysroots: ?[]const u8,
    optimize: std.builtin.OptimizeMode,

    /// Resolve a per-dependency override against the global mode, the same way
    /// cmake/LocalproxyDeps.cmake's `localproxy_resolve_mode` does.
    pub fn resolveDep(self: Options, source: DepSource) DepMode {
        return switch (source) {
            .inherit => self.dep_mode,
            .system => .system,
            .fetch => .fetch,
        };
    }
};

/// Print an actionable configure-time error and stop. build.zig has no
/// equivalent of CMake's `message(FATAL_ERROR ...)`; exiting non-zero with a
/// single clear message is the closest behavior and keeps `zig build` from
/// emitting a half-configured artifact.
pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// Does `abs_path` name something readable? Used for the `auto` dependency
/// probes and for validating user-supplied OpenSSL paths.
pub fn pathExists(io: std.Io, abs_path: []const u8) bool {
    if (std.Io.Dir.cwd().statFile(io, abs_path, .{})) |_| {
        return true;
    } else |_| {
        return false;
    }
}

/// Warning suppressions applied to vendored third-party translation units.
///
/// The CMake build compiles Boost, Protobuf and Catch2 through their own
/// projects, which do not use this repo's `-Wall -Werror`. The Zig build
/// compiles them in dedicated modules, so `-Werror` is simply never added
/// there; `-w` additionally silences the (harmless, upstream) warnings so the
/// build log stays readable. Our own translation units keep `-Wall -Werror`.
pub const third_party_flags = [_][]const u8{
    "-std=c++14",
    "-w",
};
