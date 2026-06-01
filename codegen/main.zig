const std = @import("std");
const parse = @import("parse.zig");
const meta = @import("metadata.zig");
const emit = @import("emit.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        std.log.err("usage: tl_gen <schema.tl>... <out_dir>", .{});
        return error.BadArgs;
    }

    var schema = parse.Schema.init();
    defer schema.deinit(allocator);

    for (args[1 .. args.len - 1]) |path| {
        try parse.parseFile(path, &schema, io, allocator, arena);
    }

    // Collect result types by constructor count.
    // union_types: 2+ constructors → emitted as tagged union.
    // single_types: exactly 1 constructor → emitted as plain struct, but still a named type.
    var union_types = std.StringHashMap(void).init(allocator);
    defer union_types.deinit();
    // Maps result_type → constructor_name for single-constructor types.
    // Needed so field codegen can resolve e.g. "PaymentSavedCredentials" → "paymentSavedCredentialsCard".
    var single_types = std.StringHashMap([]const u8).init(allocator);
    defer single_types.deinit();
    {
        var counts = std.StringHashMap(u32).init(allocator);
        defer counts.deinit();
        for (schema.constructors.items) |ctor| {
            if (ctor.is_function) continue;
            const res = try counts.getOrPut(ctor.result_type);
            if (!res.found_existing) res.value_ptr.* = 0;
            res.value_ptr.* += 1;
        }
        var it = counts.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* >= 2) try union_types.put(e.key_ptr.*, {});
        }
        for (schema.constructors.items) |ctor| {
            if (ctor.is_function) continue;
            if (counts.get(ctor.result_type) == 1) {
                try single_types.put(ctor.result_type, ctor.name);
            }
        }
    }

    var metadata = try meta.Metadata.init(allocator, &schema);
    defer metadata.deinit(allocator);

    const out_dir_path = args[args.len - 1];
    _ = try std.Io.Dir.cwd().createDirPathStatus(io, out_dir_path, .default_dir);

    try emit.emitTypes(&schema, &union_types, &single_types, &metadata, out_dir_path, io, allocator);
    try emit.emitUnions(&schema, &union_types, &metadata, out_dir_path, io, allocator);
    try emit.emitFunctions(&schema, &union_types, &single_types, out_dir_path, io, allocator);
}
