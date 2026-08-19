//! Minimal libc shim for wasm32-freestanding.
//!
//! `sqlite3.c` compiled with `-DSQLITE_OS_OTHER=1` still references a handful
//! of libc functions (string ops, malloc family, math, time). wasm32-freestanding
//! has no libc, so we provide them here, implemented on top of Zig's
//! `std.heap.wasm_allocator` and `std.math`.
//!
//! Only reachable functions are retained by wasm-ld (--gc-sections), so the
//! bundle stays small even though this file declares the full surface sqlite
//! may reference.
const std = @import("std");

// --- string.h ---

export fn strcmp(a: [*]const u8, b: [*]const u8) c_int {
    var i: usize = 0;
    while (true) {
        const x = a[i];
        const y = b[i];
        if (x != y) return @as(c_int, x) - @as(c_int, y);
        if (x == 0) return 0;
        i += 1;
    }
}

export fn strncmp(a: [*]const u8, b: [*]const u8, n: usize) c_int {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const x = a[i];
        const y = b[i];
        if (x != y) return @as(c_int, x) - @as(c_int, y);
        if (x == 0) return 0;
    }
    return 0;
}

export fn strlen(s: [*:0]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) i += 1;
    return i;
}

export fn strchr(s: [*]const u8, ch: c_int) ?[*]const u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        if (s[i] == ch) return s + i;
    }
    return if (ch == 0) s + i else null;
}

export fn strrchr(s: [*]const u8, ch: c_int) ?[*]const u8 {
    var i: usize = 0;
    var found: ?[*]const u8 = null;
    while (s[i] != 0) : (i += 1) {
        if (s[i] == ch) found = s + i;
    }
    return if (found) |f| f else if (ch == 0) s + i else null;
}

export fn strspn(s: [*]const u8, accept: [*]const u8) usize {
    var i: usize = 0;
    outer: while (s[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (accept[j] != 0) : (j += 1) {
            if (s[i] == accept[j]) continue :outer;
        }
        break;
    }
    return i;
}

export fn strcspn(s: [*]const u8, reject: [*]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {
        var j: usize = 0;
        while (reject[j] != 0) : (j += 1) {
            if (s[i] == reject[j]) return i;
        }
    }
    return i;
}

// --- malloc family ---
// sqlite calls free(void*) without a size, so we stash the size in a 16-byte
// header (4 bytes size + alignment slack) and keep blocks 16-byte aligned.

const allocator = std.heap.wasm_allocator;
const hdr_len = 16;

fn blockPtr(user: [*]u8) [*]u8 {
    return user - hdr_len;
}
fn userPtr(block: [*]u8) [*]u8 {
    return block + hdr_len;
}
fn blockSize(block: [*]u8) u32 {
    return std.mem.readInt(u32, block[0..4], .little);
}

export fn malloc(size: usize) ?[*]u8 {
    const block = allocator.alloc(u8, hdr_len + size) catch return null;
    std.mem.writeInt(u32, block[0..4], @intCast(size), .little);
    return userPtr(block.ptr);
}

export fn calloc(n: usize, size: usize) ?[*]u8 {
    const total = n * size;
    const p = malloc(total) orelse return null;
    @memset(p[0..total], 0);
    return p;
}

export fn free(ptr: ?[*]u8) void {
    const p = ptr orelse return;
    const block = blockPtr(p);
    allocator.free(block[0 .. hdr_len + blockSize(block)]);
}

export fn realloc(ptr: ?[*]u8, size: usize) ?[*]u8 {
    if (ptr == null) return malloc(size);
    const p = ptr.?;
    const old = blockSize(blockPtr(p));
    const np = malloc(size) orelse return null;
    @memcpy(np[0..@min(old, size)], p[0..old]);
    free(p);
    return np;
}

// --- math.h (FTS5 ranking uses these; wasm has native f64) ---

export fn sqrt(x: f64) f64 {
    return std.math.sqrt(x);
}
export fn pow(x: f64, y: f64) f64 {
    return std.math.pow(f64, x, y);
}
export fn log(x: f64) f64 {
    return std.math.log(f64, std.math.e, x);
}
export fn log10(x: f64) f64 {
    return std.math.log10(x);
}
export fn exp(x: f64) f64 {
    return std.math.exp(x);
}
export fn fabs(x: f64) f64 {
    return @abs(x);
}
export fn floor(x: f64) f64 {
    return @floor(x);
}
export fn ceil(x: f64) f64 {
    return @ceil(x);
}
export fn fmod(x: f64, y: f64) f64 {
    return @mod(x, y);
}
export fn sin(x: f64) f64 {
    return std.math.sin(x);
}
export fn cos(x: f64) f64 {
    return std.math.cos(x);
}

// --- time.h (minimal; SQLITE_OMIT_DATETIME_FUNCS keeps usage to
// currentTimeFunc: time/gmtime/strftime) ---

const time_t = i64;
const TmStruct = struct {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
};

var g_tm: TmStruct = std.mem.zeroes(TmStruct);

export fn time(t: ?*time_t) time_t {
    if (t) |p| p.* = 0;
    return 0;
}
export fn gmtime(t: ?*const time_t) *TmStruct {
    _ = t;
    return &g_tm;
}
export fn strftime(s: [*]u8, max: usize, fmt: [*:0]const u8, tm: *const TmStruct) usize {
    _ = tm;
    const f = std.mem.span(fmt);
    if (std.mem.eql(u8, f, "%H:%M:%S")) {
        const r = "00:00:00";
        if (r.len < max) @memcpy(s[0..r.len], r);
        return r.len;
    }
    if (std.mem.eql(u8, f, "%Y-%m-%d")) {
        const r = "1970-01-01";
        if (r.len < max) @memcpy(s[0..r.len], r);
        return r.len;
    }
    return 0;
}
