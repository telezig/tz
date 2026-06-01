const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const codec_module = b.createModule(.{
        .root_source_file = b.path("src/tl/codec.zig"),
        .target = target,
        .optimize = optimize,
    });

    const codegen_exe = b.addExecutable(.{
        .name = "tl_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("codegen/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run_codegen = b.addRunArtifact(codegen_exe);
    run_codegen.addFileArg(b.path("schema/mtproto.tl"));
    run_codegen.addFileArg(b.path("schema/api.tl"));
    const gen_dir = run_codegen.addOutputDirectoryArg("generated");

    const types_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "types.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "codec", .module = codec_module }},
    });
    const functions_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "functions.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = codec_module },
            .{ .name = "types", .module = types_module },
        },
    });

    const mod = b.addModule("tz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = codec_module },
            .{ .name = "types", .module = types_module },
            .{ .name = "functions", .module = functions_module },
        },
    });

    const lib = b.addLibrary(.{ .name = "tz", .root_module = mod });
    b.installArtifact(lib);

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    }).step);

    const test_step = b.step("test", "Run tests");
    for (&[_]*std.Build.Module{ mod, codec_module }) |m|
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = m })).step);

    const examples = &[_]struct { name: []const u8, extra_imports: []const std.Build.Module.Import }{
        .{ .name = "echo_bot", .extra_imports = &.{} },
        .{ .name = "any_call", .extra_imports = &.{} },
        .{ .name = "feature_demo", .extra_imports = &.{} },
        .{ .name = "user_login", .extra_imports = &.{.{ .name = "functions", .module = functions_module }} },
        .{ .name = "qr_login", .extra_imports = &.{} },
    };
    for (examples) |ex| {
        const imports = b.allocator.alloc(std.Build.Module.Import, 1 + ex.extra_imports.len) catch @panic("oom");
        imports[0] = .{ .name = "tz", .module = mod };
        @memcpy(imports[1..], ex.extra_imports);
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{ex.name})),
                .target = target,
                .optimize = optimize,
                .imports = imports,
            }),
        });
        const step_name = b.dupe(ex.name);
        std.mem.replaceScalar(u8, step_name, '_', '-');
        b.step(step_name, b.fmt("Build {s}", .{ex.name})).dependOn(&b.addInstallArtifact(exe, .{}).step);
    }

    const update_schema = b.step("update-schema", "Fetch latest TL schemas from tdesktop");
    const base = "https://raw.githubusercontent.com/telegramdesktop/tdesktop/dev/Telegram/SourceFiles/mtproto/scheme/";
    for (&[_][2][]const u8{
        .{ base ++ "mtproto.tl", "schema/mtproto.tl" },
        .{ base ++ "api.tl", "schema/api.tl" },
    }) |pair| {
        update_schema.dependOn(&b.addSystemCommand(&.{ "curl", "-fsSL", pair[0], "-o", pair[1] }).step);
    }
}
