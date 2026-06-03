const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const parse = @import("parse.zig");
const meta = @import("metadata.zig");
const names = @import("names.zig");
const Constructor = parse.Constructor;
const Metadata = meta.Metadata;

// Convert a TL type string to a Zig type string.
// `recursive_ctor` — if true, wrap the type in a pointer (only for genuinely recursive constructors).
fn tlTypeToZig(
    tl_type: []const u8,
    union_types: *const std.StringHashMap(void),
    single_types: *const std.StringHashMap([]const u8),
    arena: Allocator,
    qualify_unions: bool, // prefix with @import("tl_types").
    box: bool, // wrap union type in *
) ![]const u8 {
    if (std.mem.eql(u8, tl_type, "int")) return "i32";
    if (std.mem.eql(u8, tl_type, "long")) return "i64";
    if (std.mem.eql(u8, tl_type, "double")) return "f64";
    if (std.mem.eql(u8, tl_type, "bool") or std.mem.eql(u8, tl_type, "Bool")) return "bool";
    if (std.mem.eql(u8, tl_type, "true")) return "void";
    if (std.mem.eql(u8, tl_type, "string") or std.mem.eql(u8, tl_type, "bytes")) return "[]const u8";
    if (std.mem.eql(u8, tl_type, "int128")) return "u128";
    if (std.mem.eql(u8, tl_type, "int256")) return "[32]u8";

    // Lowercase `vector<...>` is a bare TL vector (no 0x1cb5c415, bare elements);
    // uppercase `Vector<...>` is boxed and handled by the generic `<` branch below.
    if (std.mem.startsWith(u8, tl_type, "vector<") and std.mem.endsWith(u8, tl_type, ">")) {
        const inner = try tlTypeToZig(tl_type["vector<".len .. tl_type.len - 1], union_types, single_types, arena, qualify_unions, false);
        return std.fmt.allocPrint(arena, "tl.BareVector({s})", .{inner});
    }
    if (std.mem.indexOfScalar(u8, tl_type, '<')) |lt| {
        const inner = try tlTypeToZig(tl_type[lt + 1 .. tl_type.len - 1], union_types, single_types, arena, qualify_unions, false);
        return std.fmt.allocPrint(arena, "[]const {s}", .{inner});
    }
    if (std.mem.startsWith(u8, tl_type, "Vector ")) {
        const inner = try tlTypeToZig(tl_type[7..], union_types, single_types, arena, qualify_unions, false);
        return std.fmt.allocPrint(arena, "[]const {s}", .{inner});
    }
    if (std.mem.startsWith(u8, tl_type, "%Vector ")) {
        const inner = try tlTypeToZig(tl_type[8..], union_types, single_types, arena, qualify_unions, false);
        return std.fmt.allocPrint(arena, "[]const {s}", .{inner});
    }

    if (union_types.contains(tl_type)) {
        var nb: [256]u8 = undefined;
        const zname = names.typeName(tl_type, &nb);
        const ptr = if (box) "*" else "";
        // Boxed tagged unions live in unions.zig — always qualified, even from types.zig.
        return std.fmt.allocPrint(arena, "{s}@import(\"unions\").{s}", .{ ptr, zname });
    }

    if (single_types.get(tl_type)) |ctor_name| {
        var nb: [256]u8 = undefined;
        const zname = names.typeName(ctor_name, &nb);
        if (qualify_unions)
            return std.fmt.allocPrint(arena, "@import(\"types\").{s}", .{zname});
        return std.fmt.allocPrint(arena, "{s}", .{zname});
    }

    // A bare lowercase constructor reference (e.g. `future_salt` inside
    // vector<future_salt>) names a type whose single constructor's struct we emit.
    {
        var it = single_types.iterator();
        while (it.next()) |e| {
            if (std.mem.eql(u8, e.value_ptr.*, tl_type)) {
                var nb: [256]u8 = undefined;
                const zname = names.typeName(tl_type, &nb);
                if (qualify_unions)
                    return std.fmt.allocPrint(arena, "@import(\"types\").{s}", .{zname});
                return std.fmt.allocPrint(arena, "{s}", .{zname});
            }
        }
    }

    // Bang types (!X) are templated query parameters carried as pre-serialized
    // bytes — []const u8 is the intended mapping.
    if (std.mem.startsWith(u8, tl_type, "!")) return "[]const u8";

    // Unresolved reference: default to raw bytes.
    return "[]const u8";
}

pub fn emitTypes(
    schema: *const parse.Schema,
    union_types: *const std.StringHashMap(void),
    single_types: *const std.StringHashMap([]const u8),
    metadata: *const Metadata,
    out_dir: []const u8,
    io: Io,
    allocator: Allocator,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    var tmp_arena = std.heap.ArenaAllocator.init(allocator);
    defer tmp_arena.deinit();
    const tmp = tmp_arena.allocator();

    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var kit = seen.keyIterator();
        while (kit.next()) |k| allocator.free(k.*);
        seen.deinit();
    }

    try buf.appendSlice(allocator, "const tl = @import(\"codec\");\n\n");

    var name_buf: [256]u8 = undefined;
    var field_buf: [256]u8 = undefined;

    // Emit constructor structs
    for (schema.constructors.items) |ctor| {
        if (ctor.is_function) continue;
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ ctor.result_type, ctor.name });
        const gop = try seen.getOrPut(key);
        if (gop.found_existing) {
            allocator.free(key);
            continue;
        }

        const ctor_name = names.typeName(ctor.name, &name_buf);

        try buf.print(allocator, "pub const {s} = struct {{\n", .{ctor_name});
        try buf.print(allocator, "    pub const cid: u32 = 0x{x:0>8};\n", .{ctor.id});

        const is_rec = metadata.isRecursive(ctor);
        for (ctor.params) |p| {
            if (p.is_flags) {
                const ft = if (p.flags_index == 0) "tl.Flags" else "tl.Flags2";
                try buf.print(allocator, "    {s}: {s} = .{{}},\n", .{ p.name, ft });
            } else if (p.flag_bit) |bit| {
                const fname = names.fieldName(p.name, &field_buf);
                const ftype = try tlTypeToZig(p.type_name, union_types, single_types, tmp, false, is_rec);
                if (p.flags_index == 0) {
                    try buf.print(allocator, "    {s}: tl.Flag({d}, {s}) = .none,\n", .{ fname, bit, ftype });
                } else {
                    try buf.print(allocator, "    {s}: tl.Flag2({d}, {s}) = .none,\n", .{ fname, bit, ftype });
                }
            } else {
                const fname = names.fieldName(p.name, &field_buf);
                const ftype = try tlTypeToZig(p.type_name, union_types, single_types, tmp, false, is_rec);
                const is_random_id = std.mem.eql(u8, p.name, "random_id") and std.mem.eql(u8, p.type_name, "long");
                if (is_random_id) {
                    try buf.print(allocator, "    {s}: {s} = 0,\n", .{ fname, ftype });
                } else {
                    try buf.print(allocator, "    {s}: {s},\n", .{ fname, ftype });
                }
            }
        }
        try buf.appendSlice(allocator, "};\n\n");
    }

    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/types.zig", .{out_dir});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buf.items });
}

// Emit unions.zig: one tagged union per multi-constructor TL type. Variant tags keep
// the constructor's PascalCase name (faithful to TL); payloads point into types.zig.
pub fn emitUnions(
    schema: *const parse.Schema,
    union_types: *const std.StringHashMap(void),
    metadata: *const Metadata,
    out_dir: []const u8,
    io: Io,
    allocator: Allocator,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    var groups = std.StringHashMap(std.ArrayList(Constructor)).init(allocator);
    defer {
        var vit = groups.valueIterator();
        while (vit.next()) |v| v.deinit(allocator);
        groups.deinit();
    }
    var order: std.ArrayList([]const u8) = .empty;
    defer order.deinit(allocator);

    for (schema.constructors.items) |ctor| {
        if (ctor.is_function) continue;
        if (!union_types.contains(ctor.result_type)) continue;
        const res = try groups.getOrPut(ctor.result_type);
        if (!res.found_existing) {
            res.value_ptr.* = .empty;
            try order.append(allocator, ctor.result_type);
        }
        try res.value_ptr.append(allocator, ctor);
    }

    var name_buf: [256]u8 = undefined;
    var tag_buf: [256]u8 = undefined;
    for (order.items) |result_type| {
        const ctors = (groups.get(result_type) orelse continue).items;
        const union_name = names.typeName(result_type, &name_buf);
        try buf.print(allocator, "pub const {s} = union(enum) {{\n", .{union_name});
        for (ctors) |ctor| {
            const tag = names.typeName(ctor.name, &tag_buf);
            // Recursive constructors are boxed in the union variant too.
            const star: []const u8 = if (metadata.isRecursive(ctor)) "*" else "";
            try buf.print(allocator, "    {s}: {s}@import(\"types\").{s},\n", .{ tag, star, tag });
        }
        try buf.appendSlice(allocator, "};\n\n");
    }

    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/unions.zig", .{out_dir});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buf.items });
}

pub fn emitFunctions(
    schema: *const parse.Schema,
    union_types: *const std.StringHashMap(void),
    single_types: *const std.StringHashMap([]const u8),
    out_dir: []const u8,
    io: Io,
    allocator: Allocator,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    var tmp_arena = std.heap.ArenaAllocator.init(allocator);
    defer tmp_arena.deinit();
    const tmp = tmp_arena.allocator();

    var groups = std.StringHashMap(std.ArrayList(Constructor)).init(allocator);
    defer {
        var vit = groups.valueIterator();
        while (vit.next()) |v| v.deinit(allocator);
        groups.deinit();
    }
    var category_order: std.ArrayList([]const u8) = .empty;
    defer category_order.deinit(allocator);

    for (schema.constructors.items) |ctor| {
        if (!ctor.is_function) continue;
        const cat: []const u8 = if (std.mem.indexOfScalar(u8, ctor.name, '.')) |dot|
            ctor.name[0..dot]
        else
            "";
        const res = try groups.getOrPut(cat);
        if (!res.found_existing) {
            res.value_ptr.* = .empty;
            try category_order.append(allocator, cat);
        }
        try res.value_ptr.append(allocator, ctor);
    }

    try buf.appendSlice(allocator, "const tl = @import(\"codec\");\n\n");
    try buf.print(allocator, "/// API layer version this schema was generated from (used by invokeWithLayer).\npub const layer: i32 = {d};\n\n", .{schema.layer});
    var name_buf: [256]u8 = undefined;
    var resp_buf: [256]u8 = undefined;
    var field_buf: [256]u8 = undefined;

    for (category_order.items) |cat| {
        const ctors = groups.get(cat) orelse continue;
        const indent: []const u8 = if (cat.len > 0) "    " else "";
        if (cat.len > 0) try buf.print(allocator, "pub const {s} = struct {{\n", .{cat});

        for (ctors.items) |ctor| {
            const bare_name = if (std.mem.indexOfScalar(u8, ctor.name, '.')) |dot|
                ctor.name[dot + 1 ..]
            else
                ctor.name;
            const fn_name = names.typeName(bare_name, &name_buf);
            try buf.print(allocator, "{s}pub const {s} = struct {{\n", .{ indent, fn_name });
            try buf.print(allocator, "{s}    pub const cid: u32 = 0x{x:0>8};\n", .{ indent, ctor.id });

            for (ctor.params) |p| {
                if (p.is_flags) {
                    try buf.print(allocator, "{s}    {s}: tl.Flags = .{{}},\n", .{ indent, p.name });
                } else if (p.flag_bit) |bit| {
                    const ftype = try tlTypeToZig(p.type_name, union_types, single_types, tmp, true, false);
                    const fname = names.fieldName(p.name, &field_buf);
                    try buf.print(allocator, "{s}    {s}: tl.Flag({d}, {s}) = .none,\n", .{ indent, fname, bit, ftype });
                } else {
                    const fname = names.fieldName(p.name, &field_buf);
                    const ftype = try tlTypeToZig(p.type_name, union_types, single_types, tmp, true, false);
                    const is_random_id = std.mem.eql(u8, p.name, "random_id") and std.mem.eql(u8, p.type_name, "long");
                    if (is_random_id) {
                        try buf.print(allocator, "{s}    {s}: {s} = 0,\n", .{ indent, fname, ftype });
                    } else {
                        try buf.print(allocator, "{s}    {s}: {s},\n", .{ indent, fname, ftype });
                    }
                }
            }

            if (std.mem.indexOfScalar(u8, ctor.result_type, '<') != null) {
                const resp_type = try tlTypeToZig(ctor.result_type, union_types, single_types, tmp, true, false);
                try buf.print(allocator, "{s}    pub const Response = {s};\n", .{ indent, resp_type });
            } else {
                const resp = names.typeName(ctor.result_type, &resp_buf);
                const mod: []const u8 = if (union_types.contains(ctor.result_type)) "unions" else "types";
                try buf.print(allocator, "{s}    pub const Response = @import(\"{s}\").{s};\n", .{ indent, mod, resp });
            }
            try buf.print(allocator, "{s}}};\n\n", .{indent});
        }

        if (cat.len > 0) try buf.appendSlice(allocator, "};\n\n");
    }

    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/functions.zig", .{out_dir});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buf.items });
}
