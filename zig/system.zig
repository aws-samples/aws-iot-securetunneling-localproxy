// Discovery of pre-installed ("system") dependencies for the Zig build.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This module is the single place that answers two questions the `auto` and
// `system` dependency modes rest on:
//
//   1. Is the selected target *the host*? Only then may a pre-installed
//      library be linked, because that library was built for the host's ABI.
//      `isHost` is deliberately strict -- see the comment on it.
//   2. Where does a dependency live, and is the copy found actually usable?
//      `find` walks a prefix list and returns the prefix only when the
//      caller's header-version constraint and *every* required library are
//      satisfied, mirroring what cmake/LocalproxyDeps.cmake's probe achieves
//      with `find_package(<dep> <version> COMPONENTS ...)`.
//
// The corresponding CMake comment ("a probe without them succeeds on a
// headers-only install whose compiled libraries are missing") is the reason
// both constraints exist here.

const std = @import("std");
const cfg = @import("config.zig");

/// Is `target` the machine this build is running on, ABI and glibc floor
/// included?
///
/// Everything about a system dependency -- its ABI, its libc, the glibc symbol
/// versions its objects reference -- is fixed at the moment it was installed,
/// so it may only be linked into a binary for that exact configuration. Three
/// consequences worth spelling out, because each was a real defect:
///
///   * `abi` is part of the comparison. Without it, `-Dtarget=x86_64-linux-musl`
///     on a glibc host looks native and links glibc archives into a musl
///     binary -- a plausible-looking artifact that is silently corrupt.
///   * The glibc floor is part of the comparison. `-Dtarget=x86_64-linux-gnu.2.17`
///     asks for a binary that runs on glibc 2.17; the host's libraries
///     reference whatever its own glibc exports (`pthread_join@GLIBC_2.34` on
///     a 2.35 host), so they are the wrong input for that request.
///   * A bare `-Dtarget=x86_64-linux-gnu` is *not* the host either: Zig
///     resolves an unspecified glibc version on an explicit query to its own
///     default (2.31 as of 0.16.0), not to the host's. Such a build therefore
///     needs its dependencies supplied explicitly, exactly as any other cross
///     build does.
pub fn isHost(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    return hostMatches(target.result, b.graph.host.result);
}

/// `isHost` without a `*std.Build`, so it can be unit-tested against
/// synthesized targets (see zig/tests.zig).
pub fn hostMatches(target: std.Target, host: std.Target) bool {
    if (target.cpu.arch != host.cpu.arch) return false;
    if (target.os.tag != host.os.tag) return false;
    if (target.abi != host.abi) return false;
    if (target.os.tag == .linux and target.abi.isGnu()) {
        const want = target.os.version_range.linux.glibc;
        const have = host.os.version_range.linux.glibc;
        if (want.order(have) != .eq) return false;
    }
    return true;
}

/// A usable installation of one dependency.
pub const Prefix = struct {
    /// The prefix itself (`/usr`, `/usr/local`, ...), for diagnostics.
    root: []const u8,
    /// `<root>/include`.
    include_dir: []const u8,
    /// The subdirectory of `<root>` that actually holds the libraries.
    lib_dir: []const u8,

    /// Put the headers on `mod` as `-isystem`, mirroring
    /// `include_directories(SYSTEM ${Boost_INCLUDE_DIRS})`: our own
    /// translation units build with `-Wall -Werror` and must not be held
    /// responsible for a third-party header.
    pub fn applyInclude(self: Prefix, mod: *std.Build.Module) void {
        if (isImplicitIncludeDir(self.include_dir)) return;
        mod.addSystemIncludePath(.{ .cwd_relative = self.include_dir });
    }

    /// Put the library directory on `mod` as `-L`.
    pub fn applyLib(self: Prefix, mod: *std.Build.Module) void {
        if (isImplicitLibDir(self.lib_dir)) return;
        mod.addLibraryPath(.{ .cwd_relative = self.lib_dir });
    }
};

/// Header-version constraint for a probe.
///
/// `macro` is read out of `<include_dir>/<header>` as a plain integer, which is
/// how all three dependencies encode their version (`BOOST_VERSION 108700`,
/// `GOOGLE_PROTOBUF_VERSION 3017003`, `CATCH_VERSION_MAJOR 3`). `minimum` is a
/// floor rather than an equality test on purpose: CMake's
/// `find_package(<dep> <version>)` also means "at least this version", and the
/// pinned version in fc_deps.json is what it is given.
pub const VersionCheck = struct {
    header: []const u8,
    macro: []const u8,
    minimum: u64,
};

/// Find a usable installation of one dependency.
///
/// `libs` are base names (`boost_log`, `protobuf-lite`); every one of them must
/// resolve to a real library file in the same directory, or the prefix is
/// rejected. Returns null when no prefix satisfies both constraints.
pub fn find(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
    check: VersionCheck,
    libs: []const []const u8,
) ?Prefix {
    if (!isHost(b, target)) return null;

    for (prefixes(b, options)) |root| {
        const include_dir = b.pathJoin(&.{ root, "include" });
        const version = readVersionMacro(b, include_dir, check) orelse continue;
        if (version < check.minimum) continue;

        for (libDirs(b, root, target.result)) |lib_dir| {
            if (!allLibsPresent(b, lib_dir, libs)) continue;
            return .{ .root = root, .include_dir = include_dir, .lib_dir = lib_dir };
        }
    }
    return null;
}

/// Prefixes searched for a system dependency, most specific first.
///
/// `-Ddep-prefix` comes first: it is this build's stand-in for
/// `CMAKE_PREFIX_PATH`, which the CMake build honors through `find_package`.
/// The remaining three are the conventional install locations and stand in for
/// find_package's own defaults.
pub fn prefixes(b: *std.Build, options: cfg.Options) []const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    if (options.dep_prefixes) |joined| {
        var it = std.mem.tokenizeScalar(u8, joined, ',');
        while (it.next()) |prefix| list.append(b.allocator, prefix) catch @panic("OOM");
    }
    list.appendSlice(b.allocator, &.{
        "/usr",
        "/usr/local",
        "/opt/homebrew",
    }) catch @panic("OOM");
    return list.toOwnedSlice(b.allocator) catch @panic("OOM");
}

/// Candidate library subdirectories under `prefix`, **most specific first**.
///
/// The order is load-bearing. `/usr/lib` exists on every Linux distribution,
/// so a bare `lib` tried before `lib/<multiarch>` matches unconditionally and
/// the multiarch directory that actually holds the libraries on Debian and
/// Ubuntu is never reached. Callers additionally verify that the directory
/// contains the library they want (see `allLibsPresent` and
/// `zig/openssl.zig`), so an empty or unrelated `lib64` is skipped rather than
/// latched onto.
pub fn libDirs(b: *std.Build, prefix: []const u8, target: std.Target) []const []const u8 {
    return libDirsAlloc(b.allocator, prefix, target);
}

/// `libDirs` without a `*std.Build`, so the ordering can be unit-tested (see
/// zig/tests.zig).
pub fn libDirsAlloc(
    gpa: std.mem.Allocator,
    prefix: []const u8,
    target: std.Target,
) []const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    if (multiarchTuple(target)) |m|
        list.append(gpa, join(gpa, &.{ prefix, "lib", m })) catch @panic("OOM");
    list.append(gpa, join(gpa, &.{ prefix, "lib64" })) catch @panic("OOM");
    list.append(gpa, join(gpa, &.{ prefix, "lib" })) catch @panic("OOM");
    return list.toOwnedSlice(gpa) catch @panic("OOM");
}

fn join(gpa: std.mem.Allocator, parts: []const []const u8) []const u8 {
    return std.fs.path.join(gpa, parts) catch @panic("OOM");
}

/// Debian/Ubuntu multiarch directory name for `target`, or null where the
/// convention does not apply.
pub fn multiarchTuple(target: std.Target) ?[]const u8 {
    if (target.os.tag != .linux) return null;
    return switch (target.cpu.arch) {
        .x86_64 => if (target.abi.isGnu()) "x86_64-linux-gnu" else "x86_64-linux-musl",
        .x86 => if (target.abi.isGnu()) "i386-linux-gnu" else "i386-linux-musl",
        .aarch64 => if (target.abi.isGnu()) "aarch64-linux-gnu" else "aarch64-linux-musl",
        .arm => switch (target.abi) {
            .gnueabihf => "arm-linux-gnueabihf",
            .gnueabi => "arm-linux-gnueabi",
            .musleabihf => "arm-linux-musleabihf",
            .musleabi => "arm-linux-musleabi",
            else => null,
        },
        else => null,
    };
}

/// Does `dir` hold a linkable file for every base name in `libs`?
fn allLibsPresent(b: *std.Build, dir: []const u8, libs: []const []const u8) bool {
    for (libs) |base| if (findLib(b, dir, base) == null) return false;
    return true;
}

/// Locate `lib<base>.{a,so,dylib}` in `dir`, returning the matched file name.
///
/// Static first: cmake/LocalproxyBoost.cmake sets `Boost_USE_STATIC_LIBS ON`
/// and cmake/LocalproxyProtobuf.cmake rewrites the located protobuf-lite to its
/// static path, because a static third-party link is what keeps the released
/// binaries portable.
pub fn findLib(b: *std.Build, dir: []const u8, base: []const u8) ?[]const u8 {
    const io = b.graph.io;
    for ([_][]const u8{ ".a", ".so", ".dylib" }) |ext| {
        const name = b.fmt("lib{s}{s}", .{ base, ext });
        if (cfg.pathExists(io, b.pathJoin(&.{ dir, name }))) return name;
    }
    return null;
}

/// Read `#define <macro> <integer>` out of a header, or null if the header is
/// absent or carries no such definition.
fn readVersionMacro(b: *std.Build, include_dir: []const u8, check: VersionCheck) ?u64 {
    return readVersionMacroAt(
        b.graph.io,
        b.allocator,
        b.pathJoin(&.{ include_dir, check.header }),
        check.macro,
    );
}

/// `readVersionMacro` without a `*std.Build`, so the parsing can be
/// unit-tested (see zig/tests.zig).
pub fn readVersionMacroAt(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    macro: []const u8,
) ?u64 {
    // 1 MiB is far above any of these headers and bounds a pathological file.
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch
        return null;
    // Only an integer is carried out, so the header text has no reason to
    // outlive this call even where `gpa` is a build arena.
    defer gpa.free(text);

    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "#")) continue;
        var fields = std.mem.tokenizeAny(u8, trimmed[1..], " \t");
        const directive = fields.next() orelse continue;
        if (!std.mem.eql(u8, directive, "define")) continue;
        const name = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, macro)) continue;
        const value = fields.next() orelse continue;
        return std.fmt.parseInt(u64, value, 10) catch null;
    }
    return null;
}

/// Directories the compiler already searches for headers. Adding one of these
/// explicitly is not merely redundant: `-isystem /usr/include` is ordered ahead
/// of the toolchain's own C++ headers, which can shadow them. CMake drops
/// implicit directories from the command line for the same reason
/// (CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES).
fn isImplicitIncludeDir(dir: []const u8) bool {
    return std.mem.eql(u8, dir, "/usr/include");
}

/// Directories already on the default link path.
fn isImplicitLibDir(dir: []const u8) bool {
    return std.mem.startsWith(u8, dir, "/usr/lib") or std.mem.startsWith(u8, dir, "/lib");
}
