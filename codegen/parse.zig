const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Param = struct {
    name: []const u8,
    type_name: []const u8,
    flag_bit: ?u5 = null,
    flags_index: u8 = 0,
    is_flags: bool = false,
};

pub const Constructor = struct {
    id: u32,
    name: []const u8,
    params: []Param,
    result_type: []const u8,
    is_function: bool,
};

pub const Schema = struct {
    constructors: std.ArrayList(Constructor),
    /// API layer version, parsed from the trailing `// LAYER N` marker in api.tl.
    layer: i32 = 0,

    pub fn init() Schema {
        return .{ .constructors = .empty };
    }

    pub fn deinit(self: *Schema, allocator: Allocator) void {
        self.constructors.deinit(allocator);
    }
};

// Returns null for comment/blank/section lines or malformed input.
// All slices point into `arena` (caller owns arena lifetime).
pub fn parseLine(line: []const u8, is_function: bool, arena: Allocator) !?Constructor {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "//")) return null;
    if (std.mem.startsWith(u8, trimmed, "---")) return null;

    const body = if (std.mem.endsWith(u8, trimmed, ";"))
        trimmed[0 .. trimmed.len - 1]
    else
        trimmed;

    const eq_idx = std.mem.lastIndexOf(u8, body, " = ") orelse return null;
    const lhs = std.mem.trim(u8, body[0..eq_idx], " ");
    const result_type = std.mem.trim(u8, body[eq_idx + 3 ..], " ");
    if (std.mem.indexOfScalar(u8, result_type, ' ') != null) return null;

    var tokens = std.mem.tokenizeScalar(u8, lhs, ' ');
    const name_id = tokens.next() orelse return null;

    var name: []const u8 = name_id;
    var id: u32 = 0;
    if (std.mem.indexOfScalar(u8, name_id, '#')) |hash_pos| {
        name = name_id[0..hash_pos];
        id = std.fmt.parseInt(u32, name_id[hash_pos + 1 ..], 16) catch return null;
    }

    var params: std.ArrayList(Param) = .empty;
    var flags_count: u8 = 0;
    while (tokens.next()) |token| {
        const colon = std.mem.indexOfScalar(u8, token, ':') orelse continue;
        const pname = token[0..colon];
        var type_str = token[colon + 1 ..];

        if (std.mem.indexOfAny(u8, pname, &.{ '{', '}' }) != null) continue;

        if (std.mem.eql(u8, type_str, "#")) {
            try params.append(arena, .{ .name = pname, .type_name = "#", .is_flags = true, .flags_index = flags_count });
            flags_count += 1;
            continue;
        }

        var flag_bit: ?u5 = null;
        var flags_index: u8 = 0;
        if (std.mem.startsWith(u8, type_str, "flags")) {
            if (std.mem.indexOfScalar(u8, type_str, '.')) |dot| {
                if (std.mem.indexOfScalar(u8, type_str, '?')) |q| {
                    if (q > dot) {
                        const flags_name = type_str[0..dot];
                        if (flags_name.len > 5) {
                            flags_index = std.fmt.parseInt(u8, flags_name[5..], 10) catch 0;
                        }
                        flag_bit = std.fmt.parseInt(u5, type_str[dot + 1 .. q], 10) catch null;
                        type_str = type_str[q + 1 ..];
                    }
                }
            }
        }

        try params.append(arena, .{
            .name = pname,
            .type_name = type_str,
            .flag_bit = flag_bit,
            .flags_index = flags_index,
        });
    }

    return Constructor{
        .id = id,
        .name = name,
        .params = try params.toOwnedSlice(arena),
        .result_type = result_type,
        .is_function = is_function,
    };
}

pub fn parseFile(path: []const u8, schema: *Schema, io: std.Io, gpa: Allocator, arena: Allocator) !void {
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .unlimited);
    var is_function = false;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "// LAYER ")) |pos| {
            const tail = std.mem.trim(u8, line[pos + "// LAYER ".len ..], " \t\r\n");
            if (std.fmt.parseInt(i32, tail, 10)) |n| schema.layer = n else |_| {}
            continue;
        }
        if (std.mem.indexOf(u8, line, "---functions---") != null) {
            is_function = true;
            continue;
        }
        if (std.mem.indexOf(u8, line, "---types---") != null) {
            is_function = false;
            continue;
        }
        const ctor = parseLine(line, is_function, arena) catch continue;
        if (ctor) |c| try schema.constructors.append(gpa, c);
    }
}
