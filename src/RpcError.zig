//! Structured representation of a Telegram `rpc_error`.
//!
//! Telegram returns errors as `rpc_error#2144ca19 error_code:int error_message:string`,
//! where the message is a type name optionally followed by an integer value
//! (`FLOOD_WAIT_42`, `FILE_MIGRATE_5`, `SLOWMODE_WAIT_30`). This splits the two apart
//! and exposes a few classifiers so callers can branch on an error without
//! string-matching the raw message at every call site.
//!
//! It is a plain value type: the name is copied into an inline buffer, so an
//! `RpcError` owns nothing, copies freely, and outlives the wire bytes it was parsed
//! from. That makes it safe to return by value inside a `Result(T)`.

const std = @import("std");

const RpcError = @This();

/// `rpc_error` constructor id.
pub const cid: u32 = 0x2144ca19;

/// Telegram error code: 420 FLOOD, 303 MIGRATE, 401 UNAUTHORIZED, 400 BAD_REQUEST,
/// 500 INTERNAL, -503 TIMEOUT, etc. Negative codes are transport-level.
code: i32 = 0,
/// Trailing integer parsed out of the message, if any: the wait seconds for
/// `FLOOD_WAIT_N`, the DC id for `*_MIGRATE_N`. null when there is no numeric tail.
value: ?i32 = null,
name_buf: [64]u8,
name_len: u8 = 0,

/// The error type with any trailing `_<number>` stripped, e.g. "FLOOD_WAIT".
pub fn name(self: *const RpcError) []const u8 {
    return self.name_buf[0..self.name_len];
}

/// Parse the wire bytes of an `rpc_error`, including the 4-byte constructor id.
pub fn parse(raw: []const u8) RpcError {
    // SAFETY: name_buf is always written via setName before being read; name_len guards access.
    var e: RpcError = .{ .name_buf = undefined };
    if (raw.len < 8) return e;
    e.code = std.mem.readInt(i32, raw[4..8], .little);
    const msg = readTlString(raw[8..]);
    e.setName(splitValue(msg, &e.value));
    return e;
}

fn setName(self: *RpcError, s: []const u8) void {
    const n = @min(s.len, self.name_buf.len);
    @memcpy(self.name_buf[0..n], s[0..n]);
    self.name_len = @intCast(n);
}

/// True if the error type equals `literal` exactly (ignoring any numeric tail).
pub fn is(self: *const RpcError, literal: []const u8) bool {
    return std.mem.eql(u8, self.name(), literal);
}

// Named predicates for the errors the library and examples branch on, so call
// sites don't repeat (and risk typoing) the wire strings. Use `is` for anything else.

/// 420: too many requests; `value` is the number of seconds to wait.
pub fn isFloodWait(self: *const RpcError) bool {
    return self.code == 420;
}
/// The supplied login code was wrong; re-prompt without tearing down the session.
pub fn isPhoneCodeInvalid(self: *const RpcError) bool {
    return self.is("PHONE_CODE_INVALID");
}
/// The account has 2FA enabled: follow up with `auth.checkPassword` (SRP).
pub fn isSessionPasswordNeeded(self: *const RpcError) bool {
    return self.is("SESSION_PASSWORD_NEEDED");
}
/// The 2FA password (SRP answer) was wrong; re-prompt.
pub fn isPasswordHashInvalid(self: *const RpcError) bool {
    return self.is("PASSWORD_HASH_INVALID");
}
/// The channel can't be accessed; permanent, so stop retrying it.
pub fn isChannelInvalid(self: *const RpcError) bool {
    return self.is("CHANNEL_INVALID");
}
/// 401: the session/auth key is no longer valid and must be re-established.
/// SESSION_PASSWORD_NEEDED is also a 401 but means "needs 2FA", so it's excluded.
pub fn isUnauthorized(self: *const RpcError) bool {
    return self.code == 401 and !self.isSessionPasswordNeeded();
}

/// For a 303 migrate error, the target DC id; null otherwise.
pub fn migrateDc(self: *const RpcError) ?u8 {
    if (self.code != 303) return null;
    return std.math.cast(u8, self.value orelse return null);
}

/// How long to sleep before transparently retrying, or null if the error is not
/// auto-retryable and should be surfaced to the caller. FLOOD_WAIT waits the
/// server-requested seconds; transient server faults (500 internal, -503 timeout)
/// get a short fixed backoff.
pub fn autoRetryDelayMs(self: *const RpcError) ?u64 {
    if (self.code == 420) return @as(u64, @intCast(@max(self.value orelse 0, 0))) * std.time.ms_per_s;
    if (self.code == 500 or self.code == -503) return 1000;
    return null;
}

/// Log the error at warn level.
pub fn log(self: *const RpcError) void {
    if (self.value) |v|
        std.log.warn("rpc_error {d}: {s} ({d})", .{ self.code, self.name(), v })
    else
        std.log.warn("rpc_error {d}: {s}", .{ self.code, self.name() });
}

fn readTlString(buf: []const u8) []const u8 {
    if (buf.len == 0) return &.{};
    const first = buf[0];
    if (first < 254) {
        if (1 + @as(usize, first) > buf.len) return &.{};
        return buf[1 .. 1 + first];
    }
    // 3-byte little-endian length form; error messages never reach this in practice.
    if (buf.len < 4) return &.{};
    const len = @as(usize, buf[1]) | (@as(usize, buf[2]) << 8) | (@as(usize, buf[3]) << 16);
    if (4 + len > buf.len) return &.{};
    return buf[4 .. 4 + len];
}

/// Split a trailing `_<digits>` off `msg`, writing the parsed integer into `out_value`.
fn splitValue(msg: []const u8, out_value: *?i32) []const u8 {
    const us = std.mem.lastIndexOfScalar(u8, msg, '_') orelse return msg;
    const tail = msg[us + 1 ..];
    if (tail.len == 0) return msg;
    for (tail) |ch| if (!std.ascii.isDigit(ch)) return msg;
    out_value.* = std.fmt.parseInt(i32, tail, 10) catch return msg;
    return msg[0..us];
}

// --- tests ---

/// Build rpc_error wire bytes for testing: cid + code + TL-string message.
fn encodeForTest(buf: []u8, code: i32, msg: []const u8) []const u8 {
    std.debug.assert(msg.len < 254);
    std.mem.writeInt(u32, buf[0..4], cid, .little);
    std.mem.writeInt(i32, buf[4..8], code, .little);
    buf[8] = @intCast(msg.len);
    @memcpy(buf[9 .. 9 + msg.len], msg);
    return buf[0 .. 9 + msg.len];
}

test "parse FLOOD_WAIT splits value from name" {
    var buf: [128]u8 = undefined;
    const e = RpcError.parse(encodeForTest(&buf, 420, "FLOOD_WAIT_42"));
    try std.testing.expectEqual(@as(i32, 420), e.code);
    try std.testing.expectEqualStrings("FLOOD_WAIT", e.name());
    try std.testing.expectEqual(@as(?i32, 42), e.value);
    try std.testing.expect(e.is("FLOOD_WAIT"));
    try std.testing.expectEqual(@as(?u64, 42_000), e.autoRetryDelayMs());
}

test "parse MIGRATE exposes target dc" {
    var buf: [128]u8 = undefined;
    const e = RpcError.parse(encodeForTest(&buf, 303, "PHONE_MIGRATE_5"));
    try std.testing.expectEqual(@as(?u8, 5), e.migrateDc());
    try std.testing.expectEqualStrings("PHONE_MIGRATE", e.name());
    try std.testing.expectEqual(@as(?u64, null), e.autoRetryDelayMs());
}

test "parse plain name without numeric tail" {
    var buf: [128]u8 = undefined;
    const e = RpcError.parse(encodeForTest(&buf, 400, "PHONE_CODE_INVALID"));
    try std.testing.expectEqualStrings("PHONE_CODE_INVALID", e.name());
    try std.testing.expectEqual(@as(?i32, null), e.value);
    try std.testing.expect(e.is("PHONE_CODE_INVALID"));
    try std.testing.expectEqual(@as(?u8, null), e.migrateDc());
}

test "internal errors are auto-retryable" {
    var buf: [128]u8 = undefined;
    const e500 = RpcError.parse(encodeForTest(&buf, 500, "AUTH_RESTART"));
    try std.testing.expectEqual(@as(?u64, 1000), e500.autoRetryDelayMs());
    const e503 = RpcError.parse(encodeForTest(&buf, -503, "TIMEOUT"));
    try std.testing.expectEqual(@as(?u64, 1000), e503.autoRetryDelayMs());
}

test "parse tolerates short and empty messages" {
    var buf: [128]u8 = undefined;
    const e = RpcError.parse(encodeForTest(&buf, 420, ""));
    try std.testing.expectEqualStrings("", e.name());
    try std.testing.expectEqual(@as(?i32, null), e.value);
    // Truncated buffer must not panic.
    const short = RpcError.parse(&[_]u8{ 1, 2, 3 });
    try std.testing.expectEqual(@as(i32, 0), short.code);
}
