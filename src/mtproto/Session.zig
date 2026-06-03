const Session = @This();
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const aes_ige = @import("../crypto/aes_ige.zig");
const sha = @import("../crypto/sha.zig");

auth_key: [256]u8,
auth_key_id: i64,
server_salt: i64,
session_id: i64,
seq_no: u32 = 0,
last_msg_id: i64 = 0,
time_offset: i64 = 0,
encrypt_scratch: std.ArrayListUnmanaged(u8) = .empty,
decrypt_scratch: std.ArrayListUnmanaged(u8) = .empty,

pub fn init(auth_key: [256]u8, auth_key_id: i64, server_salt: i64, io: Io) Session {
    var sid_buf: [8]u8 = undefined;
    io.random(&sid_buf);
    return .{
        .auth_key = auth_key,
        .auth_key_id = auth_key_id,
        .server_salt = server_salt,
        .session_id = @bitCast(sid_buf),
    };
}

pub fn deinit(self: *Session, allocator: Allocator) void {
    self.encrypt_scratch.deinit(allocator);
    self.decrypt_scratch.deinit(allocator);
}

pub fn correctTimeOffset(self: *Session, server_msg_id: i64, io: Io) void {
    const server_s = server_msg_id >> 32;
    const local_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const local_s: i64 = @intCast(@divTrunc(local_ns, std.time.ns_per_s));
    self.time_offset = server_s - local_s;
    std.log.debug("time_offset corrected to {}s", .{self.time_offset});
}

pub fn nextMsgId(self: *Session, io: Io) i64 {
    const now_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const unix_s = @divTrunc(now_ns, std.time.ns_per_s) + self.time_offset;
    const frac = @rem(now_ns, std.time.ns_per_s);
    const unix_s_u: u64 = @intCast(unix_s);
    const frac_u: u64 = @intCast(frac & ~@as(@TypeOf(frac), 3));
    var id: i64 = @bitCast((unix_s_u << 32) | frac_u);
    if (id <= self.last_msg_id) id = self.last_msg_id + 4;
    self.last_msg_id = id;
    return id;
}

pub fn nextSeqNo(self: *Session, content_related: bool) u32 {
    const no = self.seq_no * 2 + if (content_related) @as(u32, 1) else 0;
    if (content_related) self.seq_no += 1;
    return no;
}

// Derive aes_key and aes_iv from auth_key + msg_key per MTProto 2.0 spec.
// x=0: client→server, x=8: server→client
fn kdf(auth_key: *const [256]u8, msg_key: *const [16]u8, x: usize, key: *[32]u8, iv: *[32]u8) void {
    // sha256_a = SHA256(msg_key + auth_key[x..x+36])
    var sha_a_in: [52]u8 = undefined;
    @memcpy(sha_a_in[0..16], msg_key);
    @memcpy(sha_a_in[16..52], auth_key[x .. x + 36]);
    const sha_a = sha.sha256(&sha_a_in);

    // sha256_b = SHA256(auth_key[40+x..76+x] + msg_key)
    var sha_b_in: [52]u8 = undefined;
    @memcpy(sha_b_in[0..36], auth_key[40 + x .. 76 + x]);
    @memcpy(sha_b_in[36..52], msg_key);
    const sha_b = sha.sha256(&sha_b_in);

    // aes_key = sha256_a[0..8] + sha256_b[8..24] + sha256_a[24..32]
    @memcpy(key[0..8], sha_a[0..8]);
    @memcpy(key[8..24], sha_b[8..24]);
    @memcpy(key[24..32], sha_a[24..32]);

    // aes_iv = sha256_b[0..8] + sha256_a[8..24] + sha256_b[24..32]
    @memcpy(iv[0..8], sha_b[0..8]);
    @memcpy(iv[8..24], sha_a[8..24]);
    @memcpy(iv[24..32], sha_b[24..32]);
}

pub const EncryptResult = struct { data: []u8, msg_id: i64 };

pub fn encrypt(self: *Session, plaintext: []const u8, allocator: Allocator, io: Io, content_related: bool) !EncryptResult {
    const pad_len = blk: {
        const unpadded = plaintext.len + 32;
        const rem = (unpadded + 12) % 16;
        break :blk if (rem == 0) 12 else 12 + (16 - rem);
    };
    const inner_len = 32 + plaintext.len + pad_len;
    try self.encrypt_scratch.resize(allocator, inner_len);
    const inner = self.encrypt_scratch.items;

    const msg_id = self.nextMsgId(io);
    std.mem.writeInt(i64, inner[0..8], self.server_salt, .little);
    std.mem.writeInt(i64, inner[8..16], self.session_id, .little);
    std.mem.writeInt(i64, inner[16..24], msg_id, .little);
    std.mem.writeInt(u32, inner[24..28], self.nextSeqNo(content_related), .little);
    std.mem.writeInt(u32, inner[28..32], @intCast(plaintext.len), .little);
    @memcpy(inner[32..][0..plaintext.len], plaintext);
    io.random(inner[32 + plaintext.len ..]);

    // msg_key = SHA256(auth_key[88..120] ++ inner)[8..24]
    const msg_key_full = sha.sha256Cat(self.auth_key[88..120], inner);
    const msg_key: *const [16]u8 = msg_key_full[8..24];

    var aes_key: [32]u8 = undefined;
    var aes_iv: [32]u8 = undefined;
    kdf(&self.auth_key, msg_key, 0, &aes_key, &aes_iv);
    aes_ige.encrypt(aes_key, aes_iv, inner);

    const out = try allocator.alloc(u8, 8 + 16 + inner_len);
    std.mem.writeInt(i64, out[0..8], self.auth_key_id, .little);
    @memcpy(out[8..24], msg_key);
    @memcpy(out[24..], inner);
    return .{ .data = out, .msg_id = msg_id };
}

/// `payload` borrows `decrypt_scratch` and is only valid until the next `decrypt`
/// call. The sole caller (readLoop) consumes it synchronously before reading the
/// next frame; anything that outlives that window (async update dispatch, rpc
/// results) must copy it.
pub const DecryptResult = struct { payload: []u8, msg_id: i64 };

pub fn decrypt(self: *Session, ciphertext: []const u8, allocator: Allocator) !DecryptResult {
    if (ciphertext.len < 24) return error.TooShort;
    const frame_key_id = std.mem.readInt(i64, ciphertext[0..8], .little);
    if (frame_key_id != self.auth_key_id) {
        // Wrong key: decrypting would yield garbage and (in abridged transport)
        // desync framing. Reject the frame instead.
        return error.AuthKeyMismatch;
    }
    const msg_key: *const [16]u8 = ciphertext[8..24];
    const encrypted = ciphertext[24..];

    var aes_key: [32]u8 = undefined;
    var aes_iv: [32]u8 = undefined;
    kdf(&self.auth_key, msg_key, 8, &aes_key, &aes_iv);

    if (encrypted.len < 32 or encrypted.len % 16 != 0) return error.BadLength;
    try self.decrypt_scratch.resize(allocator, encrypted.len);
    const inner = self.decrypt_scratch.items;
    @memcpy(inner, encrypted);
    aes_ige.decrypt(aes_key, aes_iv, inner);

    const msg_id = std.mem.readInt(i64, inner[16..24], .little);
    const payload_len = std.mem.readInt(u32, inner[28..32], .little);
    if (32 + payload_len > inner.len) return error.BadLength;
    return .{ .payload = inner[32..][0..payload_len], .msg_id = msg_id };
}

test "message encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var key: [256]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i % 256);
    var session = Session.init(key, 0xdeadbeef, 12345, io);
    defer session.deinit(allocator);
    const plaintext = "Hello, MTProto 2.0!";

    // Verify client→server output has correct structure (auth_key_id + msg_key + ciphertext).
    const encrypted = try session.encrypt(plaintext, allocator, io, true);
    defer allocator.free(encrypted.data);
    try std.testing.expect(encrypted.data.len >= 24);
    try std.testing.expectEqual(session.auth_key_id, std.mem.readInt(i64, encrypted.data[0..8], .little));

    // Test server→client direction: manually build the encrypted frame using x=8
    // (the format the server sends), then verify session.decrypt recovers plaintext.
    const x: usize = 8;
    const pad_len = blk: {
        const unpadded = plaintext.len + 32;
        const rem = (unpadded + 12) % 16;
        break :blk if (rem == 0) 12 else 12 + (16 - rem);
    };
    const inner_len = 32 + plaintext.len + pad_len;
    var inner_buf: [128]u8 = undefined;
    const inner = inner_buf[0..inner_len];
    @memset(inner, 0);
    std.mem.writeInt(i64, inner[0..8], session.server_salt, .little);
    std.mem.writeInt(i64, inner[8..16], session.session_id, .little);
    std.mem.writeInt(i64, inner[16..24], 1, .little);
    std.mem.writeInt(u32, inner[24..28], 0, .little);
    std.mem.writeInt(u32, inner[28..32], @intCast(plaintext.len), .little);
    @memcpy(inner[32..][0..plaintext.len], plaintext);

    // msg_key = SHA256(auth_key[88+x..120+x] + inner)[8..24]
    const msg_key_full = sha.sha256Cat(key[88 + x .. 88 + x + 32], inner);
    const msg_key: *const [16]u8 = msg_key_full[8..24];

    var aes_key: [32]u8 = undefined;
    var aes_iv: [32]u8 = undefined;
    Session.kdf(&key, msg_key, x, &aes_key, &aes_iv);
    aes_ige.encrypt(aes_key, aes_iv, inner);

    var server_msg_buf: [256]u8 = undefined;
    const server_msg = server_msg_buf[0 .. 8 + 16 + inner_len];
    std.mem.writeInt(i64, server_msg[0..8], session.auth_key_id, .little);
    @memcpy(server_msg[8..24], msg_key);
    @memcpy(server_msg[24..], inner);

    // payload borrows session.decrypt_scratch (freed by session.deinit); don't free it here.
    const decrypted = try session.decrypt(server_msg, allocator);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted.payload);
}
