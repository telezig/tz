const std = @import("std");
const Allocator = std.mem.Allocator;
const flags = @import("flags.zig");
const isFlag = flags.isFlag;
const isFlags = flags.isFlags;
const isFlags2 = flags.isFlags2;

const cidVector: u32 = 0x1cb5c415;
const cidBoolTrue: u32 = 0x997275b5;
const cidBoolFalse: u32 = 0xbc799737;

// A spinlock-guarded i64 rather than std.atomic.Value(i64): 64-bit atomic
// ops don't lower to a native instruction on 32-bit targets (e.g. armv7).
// std.atomic.Mutex only needs an 8-bit cmpxchg, which is universally native,
// and the critical section here is a single add, so spinning is fine.
var random_id_mu: std.atomic.Mutex = .unlocked;
var random_id_counter: i64 = 0;

fn lockRandomId() void {
    while (!random_id_mu.tryLock()) {}
}

pub fn initRandom(seed: i64) void {
    lockRandomId();
    defer random_id_mu.unlock();
    random_id_counter = seed;
}

pub fn nextRandomId() i64 {
    lockRandomId();
    defer random_id_mu.unlock();
    defer random_id_counter +%= 1;
    return random_id_counter;
}

pub fn encodeAlloc(value: anytype, allocator: Allocator) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try encodeInto(value, &buf, allocator);
    return buf.toOwnedSlice(allocator);
}

pub fn encode(value: anytype, writer: *std.Io.Writer) !void {
    try encodeWriter(@TypeOf(value), value, writer);
}

fn encodeWriter(comptime T: type, value: T, w: *std.Io.Writer) anyerror!void {
    switch (@typeInfo(T)) {
        .int, .comptime_int => try w.writeInt(T, value, .little),
        .float => {
            const IntT = std.meta.Int(.unsigned, @bitSizeOf(T));
            try w.writeInt(IntT, @bitCast(value), .little);
        },
        .bool => {
            const id: u32 = if (value) cidBoolTrue else cidBoolFalse;
            try w.writeInt(u32, id, .little);
        },
        .array => |arr| {
            if (arr.child != u8) @compileError("only [N]u8 arrays supported");
            try w.writeAll(&value);
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => {
                if (ptr.child == u8 or (ptr.is_const and ptr.child == u8)) {
                    try encodeBytesWriter(value, w);
                } else {
                    try encodeVectorWriter(value, w);
                }
            },
            .one => try encodeWriter(ptr.child, value.*, w),
            else => @compileError("unsupported pointer kind"),
        },
        .@"struct" => if (comptime flags.isBareVector(T))
            try encodeBareVectorWriter(T, value, w)
        else
            try encodeStructWriter(T, value, w),
        .@"union" => try encodeUnionWriter(T, value, w),
        .void => {},
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

fn encodeBytesWriter(data: []const u8, w: *std.Io.Writer) !void {
    const len = data.len;
    const pad_zeros = [3]u8{ 0, 0, 0 };
    if (len <= 253) {
        try w.writeAll(&.{@intCast(len)});
        try w.writeAll(data);
        const total = 1 + len;
        const pad = (4 - (total % 4)) % 4;
        try w.writeAll(pad_zeros[0..pad]);
    } else {
        try w.writeAll(&.{ 254, @intCast(len & 0xff), @intCast((len >> 8) & 0xff), @intCast((len >> 16) & 0xff) });
        try w.writeAll(data);
        const total = 4 + len;
        const pad = (4 - (total % 4)) % 4;
        try w.writeAll(pad_zeros[0..pad]);
    }
}

fn encodeVectorWriter(slice: anytype, w: *std.Io.Writer) !void {
    try w.writeInt(u32, cidVector, .little);
    try w.writeInt(u32, @intCast(slice.len), .little);
    for (slice) |item| try encodeWriter(@TypeOf(item), item, w);
}

fn encodeBareVectorWriter(comptime T: type, value: T, w: *std.Io.Writer) !void {
    try w.writeInt(u32, @intCast(value.items.len), .little);
    for (value.items) |item| {
        if (comptime @typeInfo(T.Child) == .@"struct" and @hasDecl(T.Child, "cid"))
            try encodeStructBodyWriter(T.Child, item, w)
        else
            try encodeWriter(T.Child, item, w);
    }
}

fn encodeStructWriter(comptime T: type, value: T, w: *std.Io.Writer) !void {
    if (@hasDecl(T, "cid")) try w.writeInt(u32, T.cid, .little);
    try encodeStructBodyWriter(T, value, w);
}

fn encodeStructBodyWriter(comptime T: type, value: T, w: *std.Io.Writer) !void {
    inline for (std.meta.fields(T), 0..) |field, i| {
        const fv = @field(value, field.name);
        if (comptime isFlags(field.type) or isFlags2(field.type)) {
            const this_word: u1 = if (comptime isFlags(field.type)) 0 else 1;
            var bits: u32 = 0;
            inline for (std.meta.fields(T)[i + 1 ..]) |next| {
                if (comptime isFlags(next.type) or isFlags2(next.type)) break;
                if (comptime isFlag(next.type) and next.type.flag_word == this_word) {
                    if (@field(value, next.name).value != null) {
                        bits |= @as(u32, 1) << @as(u5, next.type.flag_bit);
                    }
                }
            }
            try w.writeInt(u32, bits, .little);
        } else if (comptime isFlag(field.type)) {
            if (fv.value) |inner| {
                if (comptime field.type.Inner != void) {
                    try encodeWriter(field.type.Inner, inner, w);
                }
            }
        } else {
            if (comptime std.mem.eql(u8, field.name, "random_id") and field.type == i64) {
                try encodeWriter(i64, if (fv == 0) nextRandomId() else fv, w);
            } else {
                try encodeWriter(field.type, fv, w);
            }
        }
    }
}

fn encodeUnionWriter(comptime T: type, value: T, w: *std.Io.Writer) anyerror!void {
    switch (value) {
        inline else => |variant| {
            const VT = @TypeOf(variant);
            const is_ptr = @typeInfo(VT) == .pointer;
            const BT = if (is_ptr) std.meta.Child(VT) else VT;
            const body = if (is_ptr) variant.* else variant;
            if (@hasDecl(BT, "cid")) try w.writeInt(u32, BT.cid, .little);
            if (BT != void) try encodeStructBodyWriter(BT, body, w);
        },
    }
}

fn encodeInto(value: anytype, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) Allocator.Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int => {
            const start = buf.items.len;
            try buf.resize(allocator, start + @sizeOf(T));
            std.mem.writeInt(T, buf.items[start..][0..@sizeOf(T)], value, .little);
        },
        .float => {
            const start = buf.items.len;
            try buf.resize(allocator, start + @sizeOf(T));
            const IntT = std.meta.Int(.unsigned, @bitSizeOf(T));
            std.mem.writeInt(IntT, buf.items[start..][0..@sizeOf(T)], @bitCast(value), .little);
        },
        .bool => {
            const id: u32 = if (value) cidBoolTrue else cidBoolFalse;
            try encodeInto(id, buf, allocator);
        },
        .array => |arr| {
            if (arr.child != u8) @compileError("only [N]u8 arrays supported");
            try buf.appendSlice(allocator, &value);
        },
        .pointer => |ptr| switch (ptr.size) {
            .slice => {
                if (ptr.child == u8 or (ptr.is_const and ptr.child == u8)) {
                    try encodeBytesInto(value, buf, allocator);
                } else {
                    try encodeVectorInto(value, buf, allocator);
                }
            },
            .one => try encodeInto(value.*, buf, allocator),
            else => @compileError("unsupported pointer kind"),
        },
        .@"struct" => if (comptime flags.isBareVector(T))
            try encodeBareVectorInto(T, value, buf, allocator)
        else
            try encodeStructInto(T, value, buf, allocator),
        .@"union" => try encodeUnionInto(T, value, buf, allocator),
        .void => {},
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

fn encodeBytesInto(data: []const u8, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    const len = data.len;
    if (len <= 253) {
        try buf.append(allocator, @intCast(len));
        try buf.appendSlice(allocator, data);
        const total = 1 + len;
        const pad = (4 - (total % 4)) % 4;
        try buf.appendNTimes(allocator, 0, pad);
    } else {
        try buf.append(allocator, 254);
        try buf.append(allocator, @intCast(len & 0xff));
        try buf.append(allocator, @intCast((len >> 8) & 0xff));
        try buf.append(allocator, @intCast((len >> 16) & 0xff));
        try buf.appendSlice(allocator, data);
        const total = 4 + len;
        const pad = (4 - (total % 4)) % 4;
        try buf.appendNTimes(allocator, 0, pad);
    }
}

fn encodeVectorInto(slice: anytype, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    try encodeInto(@as(u32, cidVector), buf, allocator);
    try encodeInto(@as(u32, @intCast(slice.len)), buf, allocator);
    for (slice) |item| try encodeInto(item, buf, allocator);
}

fn encodeBareVectorInto(comptime T: type, value: T, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    try encodeInto(@as(u32, @intCast(value.items.len)), buf, allocator);
    for (value.items) |item| {
        if (comptime @typeInfo(T.Child) == .@"struct" and @hasDecl(T.Child, "cid"))
            try encodeStructBodyInto(T.Child, item, buf, allocator)
        else
            try encodeInto(item, buf, allocator);
    }
}

fn encodeStructInto(comptime T: type, value: T, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    if (@hasDecl(T, "cid")) {
        const old = buf.items.len;
        try buf.resize(allocator, old + 4);
        std.mem.writeInt(u32, buf.items[old..][0..4], T.cid, .little);
    }
    try encodeStructBodyInto(T, value, buf, allocator);
}

fn encodeStructBodyInto(comptime T: type, value: T, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    inline for (std.meta.fields(T), 0..) |field, i| {
        const fv = @field(value, field.name);
        if (comptime isFlags(field.type) or isFlags2(field.type)) {
            const this_word: u1 = if (comptime isFlags(field.type)) 0 else 1;
            var bits: u32 = 0;
            inline for (std.meta.fields(T)[i + 1 ..]) |next| {
                if (comptime isFlags(next.type) or isFlags2(next.type)) break;
                if (comptime isFlag(next.type) and next.type.flag_word == this_word) {
                    if (@field(value, next.name).value != null) {
                        bits |= @as(u32, 1) << @as(u5, next.type.flag_bit);
                    }
                }
            }
            const old = buf.items.len;
            try buf.resize(allocator, old + 4);
            std.mem.writeInt(u32, buf.items[old..][0..4], bits, .little);
        } else if (comptime isFlag(field.type)) {
            if (fv.value) |inner| {
                if (comptime field.type.Inner != void) {
                    try encodeInto(inner, buf, allocator);
                }
            }
        } else {
            if (comptime std.mem.eql(u8, field.name, "random_id") and field.type == i64) {
                try encodeInto(if (fv == 0) nextRandomId() else fv, buf, allocator);
            } else {
                try encodeInto(fv, buf, allocator);
            }
        }
    }
}

fn encodeUnionInto(comptime T: type, value: T, buf: *std.ArrayListUnmanaged(u8), allocator: Allocator) !void {
    switch (value) {
        inline else => |variant| {
            const VT = @TypeOf(variant);
            const is_ptr = @typeInfo(VT) == .pointer;
            const BT = if (is_ptr) std.meta.Child(VT) else VT;
            const body = if (is_ptr) variant.* else variant;
            if (@hasDecl(BT, "cid")) {
                const old = buf.items.len;
                try buf.resize(allocator, old + 4);
                std.mem.writeInt(u32, buf.items[old..][0..4], BT.cid, .little);
            }
            if (BT != void) try encodeStructBodyInto(BT, body, buf, allocator);
        },
    }
}
