// OpenSSL resolution for the Zig build.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// OpenSSL is *never* built from source here, exactly as in
// cmake/LocalproxyOpenSSL.cmake: it configures with a Perl script rather than
// a build system Zig can drive, and README.md's stated policy is that OpenSSL
// comes from the platform so the local proxy uses the platform's globally
// configured root CAs and keeps tracking the distribution's CVE fixes. No
// version constraint is applied, matching the CMake module (the documented
// support range is OpenSSL 1.0.1+ or OpenSSL 3).
//
// The consequence, which is deliberate: a cross target has no host OpenSSL to
// find, so the builder must supply one. Rather than silently linking the
// host's x86_64 libraries into (say) an aarch64 binary, this module fails at
// configure time and names both flags and the target triple.

const std = @import("std");
const cfg = @import("config.zig");
const system = @import("system.zig");
const targets = @import("targets.zig");

/// Prefixes probed for a native OpenSSL when neither -Dopenssl-include nor
/// -Dopenssl-libdir is given. This stands in for CMake's FindOpenSSL; it is
/// intentionally short, since anything unusual is better expressed with the
/// explicit flags.
const native_prefixes = [_][]const u8{
    "/usr",
    "/usr/local",
    "/opt/homebrew/opt/openssl@3",
    "/usr/local/opt/openssl@3",
};

pub const Resolved = struct {
    include_dir: []const u8,
    lib_dir: ?[]const u8,
    /// Absolute paths to libssl/libcrypto archives, set only for a static link.
    static_libs: ?[2][]const u8 = null,
};

/// Archive names looked for under -Dopenssl-libdir when linking statically.
/// The GNU-style `lib*.a` naming holds on every target in the matrix, including
/// `x86-windows-gnu`, because that target is MinGW rather than MSVC.
const static_archive_names = [2][]const u8{ "libssl.a", "libcrypto.a" };

/// Does `dir` hold the OpenSSL libraries this build is going to link?
///
/// Merely existing is not enough. `/usr/lib` exists on every Linux
/// distribution, so a probe that accepts the first directory it can `stat`
/// latches onto it and never reaches `/usr/lib/<multiarch>`, which is where
/// Debian and Ubuntu actually put libssl -- the default build then fails on the
/// primary documented platform with `libssl-dev` correctly installed.
fn holdsOpenssl(b: *std.Build, dir: []const u8, static: bool) bool {
    const io = b.graph.io;
    if (static) {
        for (static_archive_names) |name| {
            if (!cfg.pathExists(io, b.pathJoin(&.{ dir, name }))) return false;
        }
        return true;
    }
    // Shared: accept whichever of .so/.dylib the platform uses. findLib also
    // matches .a, which is harmless -- an archive-only directory is still the
    // right answer for -Dopenssl-static=false if it is all there is.
    return system.findLib(b, dir, "ssl") != null and system.findLib(b, dir, "crypto") != null;
}

/// Either a usable OpenSSL, or the message explaining what to supply.
///
/// Resolution is reported rather than fatal so that graph construction always
/// completes: `zig build deps -Dtarget=<cross>` legitimately needs no OpenSSL,
/// and `zig build all` should name *every* target that is missing one instead
/// of dying on the first. Callers that do need OpenSSL turn `missing` into a
/// failing step, so a build that cannot link never emits an artifact either.
pub const Result = union(enum) {
    ok: Resolved,
    missing: []const u8,
};

/// Work out where OpenSSL lives for `target`.
pub fn resolve(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) Result {
    const io = b.graph.io;
    const triple = targets.nameOf(b, target);
    // Shared with the Boost/Protobuf/Catch2 probes: a pre-installed library is
    // only valid for the exact configuration it was built for, glibc floor
    // included. See system.isHost.
    const is_native = system.isHost(b, target);

    // 1. Explicit flags always win, for native and cross alike.
    var include_dir = options.openssl_include;
    var lib_dir = options.openssl_libdir;

    // Silent precedence between two ways of saying where OpenSSL is would hide
    // a typo in either one, so refuse the combination rather than picking.
    if (options.openssl_sysroots != null and (include_dir != null or lib_dir != null)) cfg.fatal(
        \\-Dopenssl-sysroots cannot be combined with -Dopenssl-include or
        \\-Dopenssl-libdir: they are two ways of saying where OpenSSL is, and honoring
        \\one silently would hide a mistake in the other.
        \\
        \\Use -Dopenssl-sysroots=<dir> for a per-triple tree (<dir>/<triple>/{{include,lib}}),
        \\or -Dopenssl-include/-Dopenssl-libdir for a single target.
    , .{});

    // 2. A per-triple sysroot tree, so `zig build all` can serve every target
    //    from one option: <dir>/<triple>/include and <dir>/<triple>/lib.
    if (include_dir == null and lib_dir == null) {
        if (options.openssl_sysroots) |root| {
            const base = b.pathJoin(&.{ root, triple });
            const inc = b.pathJoin(&.{ base, "include" });
            if (cfg.pathExists(io, b.pathJoin(&.{ inc, "openssl", "opensslv.h" }))) {
                include_dir = inc;
                // Same candidates and same verification as the native probe: a
                // sysroot unpacked from a Debian/Ubuntu package keeps libssl in
                // lib/<multiarch>, so the bare `lib` next to it is a directory
                // that exists and holds nothing.
                for (system.libDirs(b, base, target.result)) |candidate| {
                    if (holdsOpenssl(b, candidate, options.openssl_static)) {
                        lib_dir = candidate;
                        break;
                    }
                }
            }
        }
    }

    // 3. Native builds may fall back to the platform OpenSSL, which is what
    //    find_package(OpenSSL REQUIRED) does in the CMake build.
    if (include_dir == null and is_native) {
        for (native_prefixes) |prefix| {
            const inc = b.pathJoin(&.{ prefix, "include" });
            if (!cfg.pathExists(io, b.pathJoin(&.{ inc, "openssl", "opensslv.h" }))) continue;
            include_dir = inc;
            // system.libDirs puts lib/<multiarch> first; each candidate must
            // actually hold libssl/libcrypto, so an empty lib64 (or a bare
            // /usr/lib on a multiarch distribution) is skipped rather than
            // accepted and then failed on at link time.
            for (system.libDirs(b, prefix, target.result)) |candidate| {
                if (holdsOpenssl(b, candidate, options.openssl_static)) {
                    lib_dir = candidate;
                    break;
                }
            }
            break;
        }
    }

    if (include_dir == null) {
        if (is_native) {
            return .{ .missing = b.fmt(
                \\could not find OpenSSL for the host.
                \\
                \\OpenSSL is never built from source by this project (see
                \\cmake/LocalproxyOpenSSL.cmake and docs/ZIG_BUILD.md); install it with the
                \\platform package manager, or point the build at it explicitly:
                \\
                \\    zig build -Dopenssl-include=<dir with openssl/opensslv.h> \
                \\              -Dopenssl-libdir=<dir with libssl/libcrypto>
            , .{}) };
        }
        return .{ .missing = b.fmt(
            \\OpenSSL is required for target '{s}' but was not supplied.
            \\
            \\Cross targets have no host OpenSSL to discover, and this build will not
            \\link the host's libraries into a '{s}' binary. Supply a target-ABI
            \\OpenSSL (headers + libraries) one of two ways:
            \\
            \\  1. explicitly, for a single target:
            \\         zig build -Dtarget={s} \
            \\                   -Dopenssl-include=<dir with openssl/opensslv.h> \
            \\                   -Dopenssl-libdir=<dir with libssl/libcrypto>
            \\
            \\  2. as a per-triple tree, which also serves `zig build all`:
            \\         zig build -Dopenssl-sysroots=<dir>
            \\     expecting <dir>/{s}/include and <dir>/{s}/lib
            \\
            \\See docs/ZIG_BUILD.md for how to obtain one per target.
        , .{ triple, triple, triple, triple, triple }) };
    }

    var resolved = Resolved{
        .include_dir = include_dir.?,
        .lib_dir = lib_dir,
    };

    if (options.openssl_static) {
        const dir = lib_dir orelse return .{ .missing = b.fmt(
            \\-Dopenssl-static (the default, mirroring LINK_STATIC_OPENSSL=ON) needs the
            \\OpenSSL library directory for target '{s}', but it could not be determined.
            \\Pass -Dopenssl-libdir=<dir with libssl.a and libcrypto.a>, or build against a
            \\shared OpenSSL with -Dopenssl-static=false.
        , .{triple}) };
        const names = static_archive_names;
        const ssl = b.pathJoin(&.{ dir, names[0] });
        const crypto = b.pathJoin(&.{ dir, names[1] });
        for ([_][]const u8{ ssl, crypto }) |archive| {
            if (!cfg.pathExists(io, archive)) return .{ .missing = b.fmt(
                \\static OpenSSL requested for target '{s}' but '{s}' does not exist.
                \\Point -Dopenssl-libdir at a directory containing {s} and {s}, or build
                \\against a shared OpenSSL with -Dopenssl-static=false.
            , .{ triple, archive, names[0], names[1] }) };
        }
        resolved.static_libs = .{ ssl, crypto };
    }

    return .{ .ok = resolved };
}

/// Apply the resolved OpenSSL to a module that consumes it.
///
/// The headers go on with `-isystem` (addSystemIncludePath) for the same
/// reason cmake/LocalproxyBoost.cmake uses `include_directories(SYSTEM ...)`:
/// our own translation units build with -Wall -Werror and must not fail on a
/// third-party header.
pub fn link(mod: *std.Build.Module, resolved: Resolved) void {
    mod.addSystemIncludePath(.{ .cwd_relative = resolved.include_dir });
    if (resolved.static_libs) |libs| {
        // Order matters for a static link: libssl depends on libcrypto.
        for (libs) |archive| mod.addObjectFile(.{ .cwd_relative = archive });
    } else {
        if (resolved.lib_dir) |dir| mod.addLibraryPath(.{ .cwd_relative = dir });
        mod.linkSystemLibrary("ssl", .{});
        mod.linkSystemLibrary("crypto", .{});
    }
}
