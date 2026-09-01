// Protobuf 3.17.3 for the Zig build: the protobuf-lite runtime for the target,
// a host protoc for codegen, and the Message.proto code generation step.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// resources/Message.proto is `option optimize_for = LITE_RUNTIME`, so only
// libprotobuf-lite is linked into the executables -- the same as the CMake
// build, which resolves LOCALPROXY_PROTOBUF_LINK to protobuf-lite.
//
// protoc is a *host* tool: it has to run during the build, so it is always
// built for `b.graph.host` regardless of -Dtarget. Building it from the same
// pinned 3.17.3 tree the runtime comes from is what guarantees the version
// match that generated code asserts at compile time
// (PROTOBUF_MIN_PROTOC_VERSION / GOOGLE_PROTOBUF_VERSION in Message.pb.h).
// -Dprotoc=<path> mirrors LOCALPROXY_PROTOC_EXECUTABLE and skips that build.

const std = @import("std");
const cfg = @import("config.zig");

/// Version pinned by fc_deps.json. Kept here so the -Dprotoc check and the
/// documentation cannot drift from the tarball in build.zig.zon.
pub const pinned_version = "3.17.3";

/// cmake/libprotobuf-lite.cmake
const lite_files = [_][]const u8{
    "src/google/protobuf/any_lite.cc",
    "src/google/protobuf/arena.cc",
    "src/google/protobuf/arenastring.cc",
    "src/google/protobuf/extension_set.cc",
    "src/google/protobuf/field_access_listener.cc",
    "src/google/protobuf/generated_enum_util.cc",
    "src/google/protobuf/generated_message_table_driven_lite.cc",
    "src/google/protobuf/generated_message_util.cc",
    "src/google/protobuf/implicit_weak_message.cc",
    "src/google/protobuf/io/coded_stream.cc",
    "src/google/protobuf/io/io_win32.cc",
    "src/google/protobuf/io/strtod.cc",
    "src/google/protobuf/io/zero_copy_stream.cc",
    "src/google/protobuf/io/zero_copy_stream_impl.cc",
    "src/google/protobuf/io/zero_copy_stream_impl_lite.cc",
    "src/google/protobuf/map.cc",
    "src/google/protobuf/message_lite.cc",
    "src/google/protobuf/parse_context.cc",
    "src/google/protobuf/repeated_field.cc",
    "src/google/protobuf/stubs/bytestream.cc",
    "src/google/protobuf/stubs/common.cc",
    "src/google/protobuf/stubs/int128.cc",
    "src/google/protobuf/stubs/status.cc",
    "src/google/protobuf/stubs/statusor.cc",
    "src/google/protobuf/stubs/stringpiece.cc",
    "src/google/protobuf/stubs/stringprintf.cc",
    "src/google/protobuf/stubs/structurally_valid.cc",
    "src/google/protobuf/stubs/strutil.cc",
    "src/google/protobuf/stubs/time.cc",
    "src/google/protobuf/wire_format_lite.cc",
};

/// cmake/libprotobuf.cmake -- the full runtime, host-only, needed by protoc.
/// io/gzip_stream.cc is listed upstream even with protobuf_WITH_ZLIB=OFF; it
/// compiles to nothing without HAVE_ZLIB, which is exactly the manifest's
/// setting.
const full_files = [_][]const u8{
    "src/google/protobuf/any.cc",
    "src/google/protobuf/any.pb.cc",
    "src/google/protobuf/api.pb.cc",
    "src/google/protobuf/compiler/importer.cc",
    "src/google/protobuf/compiler/parser.cc",
    "src/google/protobuf/descriptor.cc",
    "src/google/protobuf/descriptor.pb.cc",
    "src/google/protobuf/descriptor_database.cc",
    "src/google/protobuf/duration.pb.cc",
    "src/google/protobuf/dynamic_message.cc",
    "src/google/protobuf/empty.pb.cc",
    "src/google/protobuf/extension_set_heavy.cc",
    "src/google/protobuf/field_mask.pb.cc",
    "src/google/protobuf/generated_message_reflection.cc",
    "src/google/protobuf/generated_message_table_driven.cc",
    "src/google/protobuf/io/gzip_stream.cc",
    "src/google/protobuf/io/printer.cc",
    "src/google/protobuf/io/tokenizer.cc",
    "src/google/protobuf/map_field.cc",
    "src/google/protobuf/message.cc",
    "src/google/protobuf/reflection_ops.cc",
    "src/google/protobuf/service.cc",
    "src/google/protobuf/source_context.pb.cc",
    "src/google/protobuf/struct.pb.cc",
    "src/google/protobuf/stubs/substitute.cc",
    "src/google/protobuf/text_format.cc",
    "src/google/protobuf/timestamp.pb.cc",
    "src/google/protobuf/type.pb.cc",
    "src/google/protobuf/unknown_field_set.cc",
    "src/google/protobuf/util/delimited_message_util.cc",
    "src/google/protobuf/util/field_comparator.cc",
    "src/google/protobuf/util/field_mask_util.cc",
    "src/google/protobuf/util/internal/datapiece.cc",
    "src/google/protobuf/util/internal/default_value_objectwriter.cc",
    "src/google/protobuf/util/internal/error_listener.cc",
    "src/google/protobuf/util/internal/field_mask_utility.cc",
    "src/google/protobuf/util/internal/json_escaping.cc",
    "src/google/protobuf/util/internal/json_objectwriter.cc",
    "src/google/protobuf/util/internal/json_stream_parser.cc",
    "src/google/protobuf/util/internal/object_writer.cc",
    "src/google/protobuf/util/internal/proto_writer.cc",
    "src/google/protobuf/util/internal/protostream_objectsource.cc",
    "src/google/protobuf/util/internal/protostream_objectwriter.cc",
    "src/google/protobuf/util/internal/type_info.cc",
    // Upstream's libprotobuf.cmake lists this test helper in the library
    // proper; keep the list identical rather than second-guessing it.
    "src/google/protobuf/util/internal/type_info_test_helper.cc",
    "src/google/protobuf/util/internal/utility.cc",
    "src/google/protobuf/util/json_util.cc",
    "src/google/protobuf/util/message_differencer.cc",
    "src/google/protobuf/util/time_util.cc",
    "src/google/protobuf/util/type_resolver_util.cc",
    "src/google/protobuf/wire_format.cc",
    "src/google/protobuf/wrappers.pb.cc",
};

/// cmake/libprotoc.cmake -- only the C++ generator is reachable from
/// `--cpp_out`, but command_line_interface.cc registers every generator, so the
/// whole list is required to link protoc.
const protoc_lib_files = [_][]const u8{
    "src/google/protobuf/compiler/code_generator.cc",
    "src/google/protobuf/compiler/command_line_interface.cc",
    "src/google/protobuf/compiler/cpp/cpp_enum.cc",
    "src/google/protobuf/compiler/cpp/cpp_enum_field.cc",
    "src/google/protobuf/compiler/cpp/cpp_extension.cc",
    "src/google/protobuf/compiler/cpp/cpp_field.cc",
    "src/google/protobuf/compiler/cpp/cpp_file.cc",
    "src/google/protobuf/compiler/cpp/cpp_generator.cc",
    "src/google/protobuf/compiler/cpp/cpp_helpers.cc",
    "src/google/protobuf/compiler/cpp/cpp_map_field.cc",
    "src/google/protobuf/compiler/cpp/cpp_message.cc",
    "src/google/protobuf/compiler/cpp/cpp_message_field.cc",
    "src/google/protobuf/compiler/cpp/cpp_padding_optimizer.cc",
    "src/google/protobuf/compiler/cpp/cpp_parse_function_generator.cc",
    "src/google/protobuf/compiler/cpp/cpp_primitive_field.cc",
    "src/google/protobuf/compiler/cpp/cpp_service.cc",
    "src/google/protobuf/compiler/cpp/cpp_string_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_doc_comment.cc",
    "src/google/protobuf/compiler/csharp/csharp_enum.cc",
    "src/google/protobuf/compiler/csharp/csharp_enum_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_field_base.cc",
    "src/google/protobuf/compiler/csharp/csharp_generator.cc",
    "src/google/protobuf/compiler/csharp/csharp_helpers.cc",
    "src/google/protobuf/compiler/csharp/csharp_map_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_message.cc",
    "src/google/protobuf/compiler/csharp/csharp_message_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_primitive_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_reflection_class.cc",
    "src/google/protobuf/compiler/csharp/csharp_repeated_enum_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_repeated_message_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_repeated_primitive_field.cc",
    "src/google/protobuf/compiler/csharp/csharp_source_generator_base.cc",
    "src/google/protobuf/compiler/csharp/csharp_wrapper_field.cc",
    "src/google/protobuf/compiler/java/java_context.cc",
    "src/google/protobuf/compiler/java/java_doc_comment.cc",
    "src/google/protobuf/compiler/java/java_enum.cc",
    "src/google/protobuf/compiler/java/java_enum_field.cc",
    "src/google/protobuf/compiler/java/java_enum_field_lite.cc",
    "src/google/protobuf/compiler/java/java_enum_lite.cc",
    "src/google/protobuf/compiler/java/java_extension.cc",
    "src/google/protobuf/compiler/java/java_extension_lite.cc",
    "src/google/protobuf/compiler/java/java_field.cc",
    "src/google/protobuf/compiler/java/java_file.cc",
    "src/google/protobuf/compiler/java/java_generator.cc",
    "src/google/protobuf/compiler/java/java_generator_factory.cc",
    "src/google/protobuf/compiler/java/java_helpers.cc",
    "src/google/protobuf/compiler/java/java_kotlin_generator.cc",
    "src/google/protobuf/compiler/java/java_map_field.cc",
    "src/google/protobuf/compiler/java/java_map_field_lite.cc",
    "src/google/protobuf/compiler/java/java_message.cc",
    "src/google/protobuf/compiler/java/java_message_builder.cc",
    "src/google/protobuf/compiler/java/java_message_builder_lite.cc",
    "src/google/protobuf/compiler/java/java_message_field.cc",
    "src/google/protobuf/compiler/java/java_message_field_lite.cc",
    "src/google/protobuf/compiler/java/java_message_lite.cc",
    "src/google/protobuf/compiler/java/java_name_resolver.cc",
    "src/google/protobuf/compiler/java/java_primitive_field.cc",
    "src/google/protobuf/compiler/java/java_primitive_field_lite.cc",
    "src/google/protobuf/compiler/java/java_service.cc",
    "src/google/protobuf/compiler/java/java_shared_code_generator.cc",
    "src/google/protobuf/compiler/java/java_string_field.cc",
    "src/google/protobuf/compiler/java/java_string_field_lite.cc",
    "src/google/protobuf/compiler/js/js_generator.cc",
    "src/google/protobuf/compiler/js/well_known_types_embed.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_enum.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_enum_field.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_extension.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_field.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_file.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_generator.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_helpers.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_map_field.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_message.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_message_field.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_oneof.cc",
    "src/google/protobuf/compiler/objectivec/objectivec_primitive_field.cc",
    "src/google/protobuf/compiler/php/php_generator.cc",
    "src/google/protobuf/compiler/plugin.cc",
    "src/google/protobuf/compiler/plugin.pb.cc",
    "src/google/protobuf/compiler/python/python_generator.cc",
    "src/google/protobuf/compiler/ruby/ruby_generator.cc",
    "src/google/protobuf/compiler/subprocess.cc",
    "src/google/protobuf/compiler/zip_writer.cc",
};

pub const Protobuf = struct {
    mode: cfg.DepMode,
    /// protobuf-lite for the selected target, null in system mode.
    lite: ?*std.Build.Step.Compile,
    /// src/ of the vendored tree, for -isystem on consumers.
    include_dir: ?std.Build.LazyPath,

    pub fn apply(self: Protobuf, mod: *std.Build.Module) void {
        if (self.include_dir) |dir| mod.addSystemIncludePath(dir);
        if (self.lite) |lib| mod.linkLibrary(lib) else mod.linkSystemLibrary("protobuf-lite", .{});
    }
};

/// cmake/CMakeLists.txt: add_definitions(-DGOOGLE_PROTOBUF_CMAKE_BUILD) plus
/// -DHAVE_PTHREAD where threads are available. HAVE_ZLIB is deliberately
/// absent (protobuf_WITH_ZLIB=OFF in fc_deps.json).
fn applyProtobufDefines(mod: *std.Build.Module, target: std.Target) void {
    mod.addCMacro("GOOGLE_PROTOBUF_CMAKE_BUILD", "1");
    if (target.os.tag != .windows) mod.addCMacro("HAVE_PTHREAD", "1");
}

fn systemProtobufFound(b: *std.Build, target: std.Build.ResolvedTarget) bool {
    if (target.result.os.tag != b.graph.host.result.os.tag or
        target.result.cpu.arch != b.graph.host.result.cpu.arch) return false;
    const io = b.graph.io;
    for ([_][]const u8{ "/usr/include", "/usr/local/include", "/opt/homebrew/include" }) |prefix| {
        if (cfg.pathExists(io, b.pathJoin(&.{ prefix, "google", "protobuf", "message_lite.h" })))
            return true;
    }
    return false;
}

/// protobuf-lite for `target`.
pub fn add(
    b: *std.Build,
    options: cfg.Options,
    target: std.Build.ResolvedTarget,
) ?Protobuf {
    const mode: cfg.DepMode = switch (options.resolveDep(options.protobuf_source)) {
        .system => .system,
        .fetch => .fetch,
        .auto => if (systemProtobufFound(b, target)) .system else .fetch,
    };
    if (mode == .system) return .{ .mode = .system, .lite = null, .include_dir = null };

    const dep = b.lazyDependency("protobuf", .{}) orelse return null;
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
    applyProtobufDefines(mod, target.result);
    mod.addCSourceFiles(.{
        .root = dep.path("."),
        .files = &lite_files,
        .flags = &cfg.third_party_flags,
        .language = .cpp,
    });

    return .{
        .mode = mode,
        .lite = b.addLibrary(.{
            .name = "protobuf-lite",
            .root_module = mod,
            .linkage = .static,
        }),
        .include_dir = dep.path("src"),
    };
}

/// The generated Message.pb.{h,cc}: a directory to put on the include path and
/// the .cc to compile into each executable.
pub const Generated = struct {
    dir: std.Build.LazyPath,
    source: std.Build.LazyPath,
};

/// Build a host protoc from the vendored 3.17.3 tree.
///
/// `.target = b.graph.host` is the whole point: a protoc cross-compiled for
/// -Dtarget could not run during the build. The CMake build hits the same wall
/// and requires LOCALPROXY_PROTOC_EXECUTABLE when cross-compiling in fetch
/// mode; here the host build is always available, so no such requirement
/// exists.
fn hostProtoc(b: *std.Build, dep: *std.Build.Dependency) *std.Build.Step.Compile {
    const host = b.graph.host;
    // protoc is a build-time tool, so optimize it for build speed rather than
    // following -Doptimize (which describes the shipped artifacts).
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const mod = b.createModule(.{
        .target = host,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
        // Zig turns clang's UBSan on by default for C/C++ in Debug and
        // ReleaseSafe. The CMake build never enables it, and a trap on
        // undefined behavior is a runtime behavior difference rather than a
        // build-configuration one, so keep the two builds equivalent.
        .sanitize_c = .off,
    });
    mod.addIncludePath(dep.path("src"));
    applyProtobufDefines(mod, host.result);

    var files = std.ArrayList([]const u8).empty;
    files.appendSlice(b.allocator, &lite_files) catch @panic("OOM");
    files.appendSlice(b.allocator, &full_files) catch @panic("OOM");
    files.appendSlice(b.allocator, &protoc_lib_files) catch @panic("OOM");
    files.append(b.allocator, "src/google/protobuf/compiler/main.cc") catch @panic("OOM");
    mod.addCSourceFiles(.{
        .root = dep.path("."),
        .files = files.toOwnedSlice(b.allocator) catch @panic("OOM"),
        .flags = &cfg.third_party_flags,
        .language = .cpp,
    });

    return b.addExecutable(.{ .name = "protoc", .root_module = mod });
}

/// Run protoc over resources/Message.proto.
///
/// Mirrors lp_protobuf_generate_cpp in cmake/LocalproxyProtobuf.cmake:
/// `protoc --cpp_out <dir> -I <proto dir> <proto>`, with the output directory
/// on the include path so sources can `#include "Message.pb.h"` unqualified
/// (CMake achieves that with include_directories(${CMAKE_CURRENT_BINARY_DIR})).
pub fn generate(b: *std.Build, options: cfg.Options) ?Generated {
    const run = if (options.protoc) |path| blk: {
        checkProtocVersion(b, path);
        break :blk b.addSystemCommand(&.{path});
    } else blk: {
        const dep = b.lazyDependency("protobuf", .{}) orelse return null;
        break :blk b.addRunArtifact(hostProtoc(b, dep));
    };

    // Reproducible-build environment, matching CMakeLists.txt's
    // set(ENV{SOURCE_DATE_EPOCH} "0") / set(ENV{ZERO_AR_DATE} "1").
    run.setEnvironmentVariable("SOURCE_DATE_EPOCH", "0");
    run.setEnvironmentVariable("ZERO_AR_DATE", "1");

    const out_dir = run.addPrefixedOutputDirectoryArg("--cpp_out=", "protogen");
    run.addPrefixedDirectoryArg("-I", b.path("resources"));
    run.addFileArg(b.path("resources/Message.proto"));

    return .{ .dir = out_dir, .source = out_dir.path(b, "Message.pb.cc") };
}

/// A user-supplied protoc must be 3.17.3: Message.pb.h asserts the generating
/// protoc's version against the linked runtime at compile time, so a mismatch
/// is a build error later and a confusing one. Fail here instead.
fn checkProtocVersion(b: *std.Build, path: []const u8) void {
    // runAllowFail only writes out_code on failure and turns a non-zero exit
    // into an error, so there is nothing to check after a successful call.
    var code: u8 = 0;
    const stdout = b.runAllowFail(&.{ path, "--version" }, &code, .ignore) catch |err| cfg.fatal(
        "-Dprotoc={s} could not be run ({s}, exit code {d})",
        .{ path, @errorName(err), code },
    );
    // Output looks like "libprotoc 3.17.3".
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    if (std.mem.indexOf(u8, trimmed, pinned_version) == null) cfg.fatal(
        \\-Dprotoc={s} reports '{s}', but protobuf {s} is required.
        \\
        \\Message.pb.h embeds a protoc-version assertion that is checked against the
        \\linked protobuf-lite runtime, so the two must match. Omit -Dprotoc to build a
        \\matching protoc from the pinned sources.
    , .{ path, trimmed, pinned_version });
}
