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
    const unions_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "unions.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "types", .module = types_module }},
    });
    // types' struct fields reference boxed unions, and unions' variants reference
    // constructor structs — the two generated modules import each other.
    types_module.addImport("unions", unions_module);

    const functions_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "functions.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = codec_module },
            .{ .name = "types", .module = types_module },
            .{ .name = "unions", .module = unions_module },
        },
    });

    // --- Core tz module: pure Zig, no sqlite, no libc.
    // Storage/Store backends (e.g. sqlite) are injected at the call site, so
    // consumers who don't need persistence never pull in sqlite3.c.
    // `store` is the shared Store vtable module (also imported by tz_db).
    const store_module = b.createModule(.{
        .root_source_file = b.path("src/Store.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mod = b.addModule("tz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = codec_module },
            .{ .name = "types", .module = types_module },
            .{ .name = "unions", .module = unions_module },
            .{ .name = "functions", .module = functions_module },
            .{ .name = "store", .module = store_module },
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

    // --- SQLite dependency & flags (shared by native and wasm backends) ---
    const sqlite_dep = b.dependency("sqlite", .{});

    const base_sqlite_flags = &[_][]const u8{
        "-std=c99",
        "-DSQLITE_DQS=0",
        "-DSQLITE_DEFAULT_MEMSTATUS=0",
        "-DSQLITE_ENABLE_FTS5=1",
        "-DSQLITE_OMIT_DEPRECATED=1",
        "-DSQLITE_OMIT_PROGRESS_CALLBACK=1",
        "-DSQLITE_OMIT_LOAD_EXTENSION=1",
        "-DSQLITE_TEMP_STORE=3",
        "-DSQLITE_OMIT_JSON=1",
        "-DSQLITE_OMIT_DATETIME_FUNCS=1",
        "-DNDEBUG=1",
    };

    const native_sqlite_flags = base_sqlite_flags ++ &[_][]const u8{
        "-DSQLITE_THREADSAFE=1",
    };

    const wasm_sqlite_flags = base_sqlite_flags ++ &[_][]const u8{
        "-DSQLITE_OS_OTHER=1",
        "-DSQLITE_THREADSAFE=0",
        "-DSQLITE_OMIT_WAL=1",
    };

    // --- Native sqlite backend module (optional; consumers import "tz_db").
    // Used by CLI/desktop builds that want local message history, or by tests.
    // `store` is wired to the core Store vtable (same file both sides use).
    const db_mod = b.addModule("tz_db", .{
        .root_source_file = b.path("src/db.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_mod.addImport("store", store_module);
    db_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = native_sqlite_flags,
    });
    db_mod.addIncludePath(sqlite_dep.path(""));
    db_mod.link_libc = true;

    const test_step = b.step("test", "Run tests");
    for (&[_]*std.Build.Module{ mod, codec_module, db_mod }) |m|
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = m })).step);

    const examples = &[_]struct { name: []const u8, extra_imports: []const std.Build.Module.Import }{
        .{ .name = "echo_bot", .extra_imports = &.{} },
        .{ .name = "any_call", .extra_imports = &.{} },
        .{ .name = "feature_demo", .extra_imports = &.{} },
        .{ .name = "user_login", .extra_imports = &.{.{ .name = "functions", .module = functions_module }} },
        .{ .name = "qr_login", .extra_imports = &.{} },
        .{ .name = "bot_store", .extra_imports = &.{.{ .name = "tz_db", .module = db_mod }} },
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

    // --- WebAssembly Target ---
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    // --- SQLite WASM backend (src/db/wasm_db.zig): sqlite3.c compiled for
    // wasm32-freestanding with SQLITE_OS_OTHER, OPFS VFS, and a libc shim.
    const wasm_db_mod = b.createModule(.{
        .root_source_file = b.path("src/db/wasm_db.zig"),
        .target = wasm_target,
        .optimize = optimize,
    });
    wasm_db_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = wasm_sqlite_flags,
    });
    wasm_db_mod.addIncludePath(sqlite_dep.path(""));
    // wasm32-freestanding ships no libc headers; sqlite3.c needs stubs.
    wasm_db_mod.addIncludePath(b.path("src/db/wasm_headers"));

    const wasm_db_exe = b.addExecutable(.{
        .name = "tz-db",
        .root_module = wasm_db_mod,
    });
    wasm_db_exe.entry = .disabled;
    wasm_db_exe.rdynamic = true;

    const wasm_db_install = b.addInstallArtifact(wasm_db_exe, .{
        .dest_dir = .{ .override = .{ .custom = "web" } },
    });
    const install_db_bench_html = b.addInstallFileWithDir(b.path("web/db-bench.html"), .{ .custom = "web" }, "db-bench.html");
    const install_db_bench_worker = b.addInstallFileWithDir(b.path("web/db-bench-worker.js"), .{ .custom = "web" }, "db-bench-worker.js");
    const install_store_demo_html = b.addInstallFileWithDir(b.path("web/store-demo.html"), .{ .custom = "web" }, "store-demo.html");
    const install_store_demo_worker = b.addInstallFileWithDir(b.path("web/store-demo-worker.js"), .{ .custom = "web" }, "store-demo-worker.js");
    const install_sdk_demo_html = b.addInstallFileWithDir(b.path("web/web-sdk-demo.html"), .{ .custom = "web" }, "web-sdk-demo.html");
    const install_sdk_demo_worker = b.addInstallFileWithDir(b.path("web/web-sdk-demo-worker.js"), .{ .custom = "web" }, "web-sdk-demo-worker.js");

    const wasm_db_step = b.step("wasm-db", "Build SQLite WASM + OPFS benchmark (zig-out/web/tz-db.wasm)");
    wasm_db_step.dependOn(&wasm_db_install.step);
    wasm_db_step.dependOn(&install_db_bench_html.step);
    wasm_db_step.dependOn(&install_db_bench_worker.step);
    wasm_db_step.dependOn(&install_store_demo_html.step);
    wasm_db_step.dependOn(&install_store_demo_worker.step);
    wasm_db_step.dependOn(&install_sdk_demo_html.step);
    wasm_db_step.dependOn(&install_sdk_demo_worker.step);

    // --- MTProto WASM demo (existing; independent of sqlite) ---
    const wasm_codec_module = b.createModule(.{
        .root_source_file = b.path("src/tl/codec.zig"),
        .target = wasm_target,
        .optimize = optimize,
    });

    const wasm_types_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "types.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .imports = &.{.{ .name = "codec", .module = wasm_codec_module }},
    });
    const wasm_unions_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "unions.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .imports = &.{.{ .name = "types", .module = wasm_types_module }},
    });
    wasm_types_module.addImport("unions", wasm_unions_module);

    const wasm_functions_module = b.createModule(.{
        .root_source_file = gen_dir.path(b, "functions.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = wasm_codec_module },
            .{ .name = "types", .module = wasm_types_module },
            .{ .name = "unions", .module = wasm_unions_module },
        },
    });

    const wasm_tz_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "codec", .module = wasm_codec_module },
            .{ .name = "types", .module = wasm_types_module },
            .{ .name = "unions", .module = wasm_unions_module },
            .{ .name = "functions", .module = wasm_functions_module },
        },
    });

    const wasm_exe = b.addExecutable(.{
        .name = "tz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm.zig"),
            .target = wasm_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tz", .module = wasm_tz_mod },
                .{ .name = "codec", .module = wasm_codec_module },
                .{ .name = "types", .module = wasm_types_module },
                .{ .name = "unions", .module = wasm_unions_module },
                .{ .name = "functions", .module = wasm_functions_module },
            },
        }),
    });
    wasm_exe.entry = .disabled;
    wasm_exe.rdynamic = true;

    const wasm_install = b.addInstallArtifact(wasm_exe, .{
        .dest_dir = .{ .override = .{ .custom = "web" } },
    });
    const install_web_html = b.addInstallFileWithDir(b.path("web/index.html"), .{ .custom = "web" }, "index.html");
    const install_web_js = b.addInstallFileWithDir(b.path("web/tz-ws.js"), .{ .custom = "web" }, "tz-ws.js");

    const wasm_step = b.step("wasm", "Build WebAssembly binary and demo (zig-out/web/)");
    wasm_step.dependOn(&wasm_install.step);
    wasm_step.dependOn(&install_web_html.step);
    wasm_step.dependOn(&install_web_js.step);
}
