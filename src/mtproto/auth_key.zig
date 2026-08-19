const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("../Transport.zig");
const sha = @import("../crypto/sha.zig");
const rsa = @import("../crypto/rsa.zig");
const dh = @import("../crypto/dh.zig");
const aes_ige = @import("../crypto/aes_ige.zig");
const ser = @import("codec").serialize;
const de = @import("codec").deserialize;

const serverKeyN: [256]u8 = .{
    0xc1, 0x50, 0x02, 0x3e, 0x2f, 0x70, 0xdb, 0x79, 0x85, 0xde, 0xd0, 0x64, 0x75, 0x9c, 0xfe, 0xcf,
    0x0a, 0xf3, 0x28, 0xe6, 0x9a, 0x41, 0xda, 0xf4, 0xd6, 0xf0, 0x1b, 0x53, 0x81, 0x35, 0xa6, 0xf9,
    0x1f, 0x8f, 0x8b, 0x2a, 0x0e, 0xc9, 0xba, 0x97, 0x20, 0xce, 0x35, 0x2e, 0xfc, 0xf6, 0xc5, 0x68,
    0x0f, 0xfc, 0x42, 0x4b, 0xd6, 0x34, 0x86, 0x49, 0x02, 0xde, 0x0b, 0x4b, 0xd6, 0xd4, 0x9f, 0x4e,
    0x58, 0x02, 0x30, 0xe3, 0xae, 0x97, 0xd9, 0x5c, 0x8b, 0x19, 0x44, 0x2b, 0x3c, 0x0a, 0x10, 0xd8,
    0xf5, 0x63, 0x3f, 0xec, 0xed, 0xd6, 0x92, 0x6a, 0x7f, 0x6d, 0xab, 0x0d, 0xdb, 0x7d, 0x45, 0x7f,
    0x9e, 0xa8, 0x1b, 0x84, 0x65, 0xfc, 0xd6, 0xff, 0xfe, 0xed, 0x11, 0x40, 0x11, 0xdf, 0x91, 0xc0,
    0x59, 0xca, 0xed, 0xaf, 0x97, 0x62, 0x5f, 0x6c, 0x96, 0xec, 0xc7, 0x47, 0x25, 0x55, 0x69, 0x34,
    0xef, 0x78, 0x1d, 0x86, 0x6b, 0x34, 0xf0, 0x11, 0xfc, 0xe4, 0xd8, 0x35, 0xa0, 0x90, 0x19, 0x6e,
    0x9a, 0x5f, 0x0e, 0x44, 0x49, 0xaf, 0x7e, 0xb6, 0x97, 0xdd, 0xb9, 0x07, 0x64, 0x94, 0xca, 0x5f,
    0x81, 0x10, 0x4a, 0x30, 0x5b, 0x6d, 0xd2, 0x76, 0x65, 0x72, 0x2c, 0x46, 0xb6, 0x0e, 0x5d, 0xf6,
    0x80, 0xfb, 0x16, 0xb2, 0x10, 0x60, 0x7e, 0xf2, 0x17, 0x65, 0x2e, 0x60, 0x23, 0x6c, 0x25, 0x5f,
    0x6a, 0x28, 0x31, 0x5f, 0x40, 0x83, 0xa9, 0x67, 0x91, 0xd7, 0x21, 0x4b, 0xf6, 0x4c, 0x1d, 0xf4,
    0xfd, 0x0d, 0xb1, 0x94, 0x4f, 0xb2, 0x6a, 0x2a, 0x57, 0x03, 0x1b, 0x32, 0xee, 0xe6, 0x4a, 0xd1,
    0x5a, 0x8b, 0xa6, 0x88, 0x85, 0xcd, 0xe7, 0x4a, 0x5b, 0xfc, 0x92, 0x0f, 0x6a, 0xbf, 0x59, 0xba,
    0x5c, 0x75, 0x50, 0x63, 0x73, 0xe7, 0x13, 0x0f, 0x90, 0x42, 0xda, 0x92, 0x21, 0x79, 0x25, 0x1f,
};
const serverKeyFp: i64 = -4344800451088585951;

pub const Result = struct {
    auth_key: [256]u8,
    auth_key_id: i64,
    server_salt: i64,
    time_offset: i32,
};

/// Sans-I/O DH handshake state machine.
///
/// Drives the 4-round key exchange (req_pq_multi → resPQ → req_DH_params →
/// server_DH_params_ok → set_client_DH_params → dh_gen_ok) with no blocking
/// I/O: the caller feeds each plain response payload and gets back either the
/// next request payload to send, or the final Result. Both native (TCP read
/// loop) and wasm (WebSocket onmessage) drive the exact same state machine.
///
/// Plain-message framing (20-byte header + padding) is NOT part of this state
/// machine — it belongs to the transport. Callers send/receive already-framed
/// payloads via their transport's plain-message helpers.
pub const AuthKey = struct {
    entropy: @import("Session.zig").Entropy,

    stage: Stage = .req_pq,

    nonce: [16]u8 = undefined,
    server_nonce: [16]u8 = undefined,
    new_nonce: [32]u8 = undefined,
    tmp_key: [32]u8 = undefined,
    tmp_iv: [32]u8 = undefined,
    dh_prime: [256]u8 = undefined,
    g_a: [256]u8 = undefined,
    b_bytes: [256]u8 = undefined,
    dh_g: u32 = 0,
    server_time: i32 = 0,

    pub const Stage = enum { req_pq, req_dh, set_client_dh, done };

    pub fn init(entropy: @import("Session.zig").Entropy) AuthKey {
        return .{ .entropy = entropy };
    }

    fn rand(self: *AuthKey, buf: []u8) void {
        self.entropy.random(buf);
    }

    /// Round 1: build the req_pq_multi request. Caller sends it. The server's
    /// resPQ response is then fed to `step`.
    pub fn start(self: *AuthKey, buf: []u8) ![]u8 {
        self.rand(&self.nonce);
        var w: std.Io.Writer = .fixed(buf);
        try w.writeInt(u32, 0xbe7e8ef1, .little); // req_pq_multi
        try w.writeAll(&self.nonce);
        return w.buffered();
    }

    /// Feed one plain response payload, advance the state machine. Returns
    /// either the next request payload to send (caller frames + sends it), or
    /// the completed handshake result. `buf` is scratch for the output; the
    /// returned slice borrows it.
    pub fn step(self: *AuthKey, response: []const u8, allocator: Allocator, buf: []u8) !StepResult {
        return switch (self.stage) {
            .req_pq => self.stepResPq(response, allocator, buf),
            .req_dh => self.stepServerDh(response, allocator, buf),
            .set_client_dh => self.stepDhGen(response),
            .done => error.AlreadyDone,
        };
    }

    pub const StepResult = union(enum) {
        send: []u8, // borrows buf
        done: Result,
    };

    fn stepResPq(self: *AuthKey, response: []const u8, allocator: Allocator, buf: []u8) !StepResult {
        var r: std.Io.Reader = .fixed(response);
        const ctor_id = try r.takeInt(u32, .little);
        if (ctor_id != 0x05162463) return error.UnexpectedResponse;
        var nonce_echo: [16]u8 = undefined;
        try r.readSliceAll(&nonce_echo);
        try r.readSliceAll(&self.server_nonce);
        const pq_bytes = try de.bytes(&r, allocator);
        defer allocator.free(pq_bytes);
        var pq: u64 = 0;
        for (pq_bytes) |b| pq = pq * 256 + b;

        const factors = factorPQ(pq, self.entropy);

        var p_bytes: [4]u8 = undefined;
        var q_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &p_bytes, factors.p, .big);
        std.mem.writeInt(u32, &q_bytes, factors.q, .big);
        self.rand(&self.new_nonce);

        var inner_buf: [256]u8 = undefined;
        var iw: std.Io.Writer = .fixed(&inner_buf);
        try iw.writeInt(u32, 0x83c95aec, .little); // p_q_inner_data_dc
        try ser.bytes(&iw, pq_bytes);
        try ser.bytes(&iw, &p_bytes);
        try ser.bytes(&iw, &q_bytes);
        try iw.writeAll(&self.nonce);
        try iw.writeAll(&self.server_nonce);
        try iw.writeAll(&self.new_nonce);

        const inner_data = iw.buffered();
        const inner_hash = sha.sha1(inner_data);
        var rsa_payload: [255]u8 = undefined;
        @memcpy(rsa_payload[0..20], &inner_hash);
        const copy_len = @min(inner_data.len, 235);
        @memcpy(rsa_payload[20..][0..copy_len], inner_data[0..copy_len]);
        self.rand(rsa_payload[20 + copy_len ..]);

        var encrypted_data: [256]u8 = undefined;
        try rsa.rsaEncrypt(&encrypted_data, &rsa_payload, serverKeyN[0..256], allocator);

        var w2: std.Io.Writer = .fixed(buf);
        try w2.writeInt(u32, 0xd712e4be, .little); // req_DH_params
        try w2.writeAll(&self.nonce);
        try w2.writeAll(&self.server_nonce);
        try ser.bytes(&w2, &p_bytes);
        try ser.bytes(&w2, &q_bytes);
        try w2.writeInt(i64, serverKeyFp, .little);
        try ser.bytes(&w2, &encrypted_data);

        self.stage = .req_dh;
        return .{ .send = w2.buffered() };
    }

    fn stepServerDh(self: *AuthKey, response: []const u8, allocator: Allocator, buf: []u8) !StepResult {
        var dhr: std.Io.Reader = .fixed(response);
        const dh_id = try dhr.takeInt(u32, .little);
        if (dh_id != 0xd0e8075c) return error.DhParamsFailed;
        var skip16: [16]u8 = undefined;
        try dhr.readSliceAll(&skip16);
        try dhr.readSliceAll(&skip16);
        const enc_answer = try de.bytes(&dhr, allocator);
        defer allocator.free(enc_answer);

        // Decrypt server_DH_inner_data
        const sha1_ns = sha.sha1Cat(&.{ &self.new_nonce, &self.server_nonce });
        const sha1_sn = sha.sha1Cat(&.{ &self.server_nonce, &self.new_nonce });
        const sha1_nn = sha.sha1Cat(&.{ &self.new_nonce, &self.new_nonce });
        @memcpy(self.tmp_key[0..20], &sha1_ns);
        @memcpy(self.tmp_key[20..32], sha1_sn[0..12]);
        @memcpy(self.tmp_iv[0..8], sha1_sn[12..20]);
        @memcpy(self.tmp_iv[8..28], &sha1_nn);
        @memcpy(self.tmp_iv[28..32], self.new_nonce[0..4]);

        const answer_buf = try allocator.dupe(u8, enc_answer);
        defer allocator.free(answer_buf);
        aes_ige.decrypt(self.tmp_key, self.tmp_iv, answer_buf);

        var ansr: std.Io.Reader = .fixed(answer_buf[20..]);
        const inner_id = try ansr.takeInt(u32, .little);
        if (inner_id != 0xb5890dba) return error.BadInnerData;
        try ansr.discardAll(16);
        try ansr.discardAll(16);
        const dh_g = try ansr.takeInt(u32, .little);
        const dh_prime_bytes = try de.bytes(&ansr, allocator);
        defer allocator.free(dh_prime_bytes);
        const g_a_bytes = try de.bytes(&ansr, allocator);
        defer allocator.free(g_a_bytes);
        const server_time = try ansr.takeInt(i32, .little);
        self.dh_g = dh_g;
        self.server_time = server_time;

        @memset(&self.dh_prime, 0);
        @memset(&self.g_a, 0);
        if (dh_prime_bytes.len <= 256) @memcpy(self.dh_prime[256 - dh_prime_bytes.len ..], dh_prime_bytes);
        if (g_a_bytes.len <= 256) @memcpy(self.g_a[256 - g_a_bytes.len ..], g_a_bytes);
        self.rand(&self.b_bytes);
        const dh_result = try dh.compute(.{ .dh_prime = self.dh_prime, .g = dh_g }, &self.g_a, &self.b_bytes, allocator);
        self.dh_prime = dh_result.secret; // stash shared secret for dh_gen

        var ci_data_buf: [320]u8 = undefined;
        var ciw: std.Io.Writer = .fixed(&ci_data_buf);
        try ciw.writeInt(u32, 0x6643b654, .little); // client_DH_inner_data
        try ciw.writeAll(&self.nonce);
        try ciw.writeAll(&self.server_nonce);
        try ciw.writeInt(i64, 0, .little);
        try ser.bytes(&ciw, &dh_result.g_b);
        const ci_data = ciw.buffered();
        const ci_hash = sha.sha1(ci_data);

        const ci_total = 20 + ci_data.len;
        const ci_padded_len = ((ci_total + 15) / 16) * 16;
        std.debug.assert(ci_padded_len <= 352);
        var ci_padded_buf: [352]u8 = undefined;
        const ci_padded = ci_padded_buf[0..ci_padded_len];
        @memcpy(ci_padded[0..20], &ci_hash);
        @memcpy(ci_padded[20..][0..ci_data.len], ci_data);
        self.rand(ci_padded[20 + ci_data.len ..]);
        aes_ige.encrypt(self.tmp_key, self.tmp_iv, ci_padded);

        var sw: std.Io.Writer = .fixed(buf);
        try sw.writeInt(u32, 0xf5045f1f, .little); // set_client_DH_params
        try sw.writeAll(&self.nonce);
        try sw.writeAll(&self.server_nonce);
        try ser.bytes(&sw, ci_padded);

        self.stage = .set_client_dh;
        return .{ .send = sw.buffered() };
    }

    fn stepDhGen(self: *AuthKey, response: []const u8) !StepResult {
        if (response.len < 4) return error.TooShort;
        const gen_id = std.mem.readInt(u32, response[0..4], .little);
        if (gen_id != 0x3bcbf734) return error.DhGenFailed;

        const auth_key_hash = sha.sha1(&self.dh_prime);
        // SAFETY: immediately overwritten by memcpy from auth_key_hash slice
        var auth_key_id: i64 = undefined;
        @memcpy(std.mem.asBytes(&auth_key_id), auth_key_hash[12..20]);

        // SAFETY: every byte is written by the XOR loop below
        var server_salt: i64 = undefined;
        for (std.mem.asBytes(&server_salt), self.new_nonce[0..8], self.server_nonce[0..8]) |*o, a, b| o.* = a ^ b;

        self.stage = .done;
        return .{ .done = Result{
            .auth_key = self.dh_prime,
            .auth_key_id = auth_key_id,
            .server_salt = server_salt,
            .time_offset = blk: {
                const now_ms = self.entropy.nowMs();
                const now_s: i32 = @intCast(@divTrunc(now_ms, std.time.ms_per_s));
                break :blk self.server_time - now_s;
            },
        } };
    }
};

fn randU64(entropy: @import("Session.zig").Entropy) u64 {
    var buf: [8]u8 = undefined;
    entropy.random(&buf);
    return @bitCast(buf);
}

fn factorPQ(pq: u64, entropy: @import("Session.zig").Entropy) struct { p: u32, q: u32 } {
    if (pq % 2 == 0) return .{ .p = 2, .q = @intCast(pq / 2) };
    var x: u64 = randU64(entropy) % (pq - 2) + 2;
    var y = x;
    const c: u64 = randU64(entropy) % (pq - 1) + 1;
    var d: u64 = 1;
    while (d == 1) {
        x = @intCast((@as(u128, x) * @as(u128, x) + @as(u128, c)) % @as(u128, pq));
        y = @intCast((@as(u128, y) * @as(u128, y) + @as(u128, c)) % @as(u128, pq));
        y = @intCast((@as(u128, y) * @as(u128, y) + @as(u128, c)) % @as(u128, pq));
        d = gcd(if (x > y) x - y else y - x, pq);
    }
    if (d == pq) return factorPQ(pq, entropy);
    const p: u32 = @intCast(d);
    const q: u32 = @intCast(pq / d);
    return if (p < q) .{ .p = p, .q = q } else .{ .p = q, .q = p };
}

fn gcd(a: u64, b: u64) u64 {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

// --- Blocking convenience wrapper (native path) ---
// Drives the AuthKey state machine over a Transport: sends each request via
// plain framing, reads each response, feeds it to step(). Kept so native
// Connector and any blocking caller get the same behavior as before; the
// state machine itself is the shared, testable core.

fn readPlainMsg(transport: *Transport, io: Io, allocator: Allocator) ![]u8 {
    const frame = try transport.readFrame(io, allocator);
    errdefer allocator.free(frame);
    if (frame.len < 20) return error.TooShort;
    const payload_len = std.mem.readInt(u32, frame[16..20], .little);
    if (20 + payload_len > frame.len) return error.BadLength;
    const payload = try allocator.dupe(u8, frame[20..][0..payload_len]);
    allocator.free(frame);
    return payload;
}

fn writePlainMsg(transport: *Transport, io: Io, payload: []const u8) !void {
    const frame_len = 20 + payload.len;
    const padded = ((frame_len + 3) / 4) * 4;
    std.debug.assert(padded <= 544);
    var frame_buf: [544]u8 = undefined;
    const frame = frame_buf[0..padded];
    @memset(frame, 0);
    std.mem.writeInt(i64, frame[0..8], 0, .little);
    const now_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const unix_s: u64 = @intCast(@divTrunc(now_ns, std.time.ns_per_s));
    const frac: u64 = @intCast(@rem(now_ns, std.time.ns_per_s) & ~@as(i128, 3));
    const msg_id: i64 = @bitCast((unix_s << 32) | frac);
    std.mem.writeInt(i64, frame[8..16], msg_id, .little);
    std.mem.writeInt(u32, frame[16..20], @intCast(payload.len), .little);
    @memcpy(frame[20..][0..payload.len], payload);
    try transport.writeFrame(io, frame);
}

pub fn perform(transport: *Transport, io: Io, allocator: Allocator) !Result {
    var ak = AuthKey.init(@import("Session.zig").ioEntropy(io));

    // Round 1: send req_pq_multi
    var buf: [512]u8 = undefined;
    const req = try ak.start(&buf);
    try writePlainMsg(transport, io, req);

    // Feed each response, send each request, until done.
    while (true) {
        const resp = try readPlainMsg(transport, io, allocator);
        defer allocator.free(resp);
        switch (try ak.step(resp, allocator, &buf)) {
            .send => |next| try writePlainMsg(transport, io, next),
            .done => |result| return result,
        }
    }
}

test "AuthKey state machine: start builds req_pq_multi" {
    var ak = AuthKey.init(@import("Session.zig").Entropy{ .js = .{
        .random = struct {
            fn f(buf: []u8) void {
                @memset(buf, 0x42);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 1700000000000;
            }
        }.f,
    } });
    var buf: [512]u8 = undefined;
    const req = try ak.start(&buf);
    try std.testing.expectEqual(@as(u32, 0xbe7e8ef1), std.mem.readInt(u32, req[0..4], .little));
    // nonce follows
    try std.testing.expectEqual(@as(usize, 20), req.len);
    try std.testing.expectEqual(@as(u8, 0x42), req[4]);
    // stage advanced
    try std.testing.expectEqual(AuthKey.Stage.req_pq, ak.stage);
}

test "AuthKey state machine: resPQ rejected for wrong ctor" {
    var ak = AuthKey.init(@import("Session.zig").Entropy{ .js = .{
        .random = struct {
            fn f(buf: []u8) void {
                @memset(buf, 0x11);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 0;
            }
        }.f,
    } });
    var buf: [512]u8 = undefined;
    _ = try ak.start(&buf);
    // wrong ctor id
    const bad = [_]u8{ 0x01, 0x00, 0x00, 0x00 } ** 4;
    try std.testing.expectError(error.UnexpectedResponse, ak.step(&bad, std.testing.allocator, &buf));
}
