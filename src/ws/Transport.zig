//! WebSocket Transport Framing and Stream Decoder for Telegram MTProto.
//!
//! Telegram MTProto over WebSocket requires Transport Obfuscation (Obfuscated2, AES-256-CTR)
//! with Padded Intermediate (0xdddddddd), Intermediate (0xeeeeeeee), or Abridged (0xef) envelopes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const aes_ctr = @import("../crypto/aes_ctr.zig");

pub const Mode = enum {
    obfuscated2_intermediate, // Obfuscated2 (64B init) wrapping Intermediate (0xeeeeeeee)
    obfuscated2_padded,       // Obfuscated2 (64B init) wrapping Padded Intermediate (0xdddddddd)
    obfuscated2_abridged,     // Obfuscated2 (64B init) wrapping Abridged (0xef)
    plain_intermediate,       // Unobfuscated Intermediate ([4B len][payload])
    plain_abridged,           // Unobfuscated Abridged ([1B len][payload])
};

pub const ObfuscatedState = struct {
    enc_stream: aes_ctr.Stream,
    dec_stream: aes_ctr.Stream,
    init_payload: [64]u8,

    pub fn init(random_fn: *const fn ([]u8) void, protocol_tag: [4]u8, dc_id: i16) ObfuscatedState {
        var init_buf: [64]u8 = undefined;
        while (true) {
            random_fn(&init_buf);
            const first = init_buf[0];
            if (first == 0xef or first == 0xee or first == 0xdd) continue;

            const tag = std.mem.readInt(u32, init_buf[0..4], .little);
            // Must not match HTTP verbs or known protocol headers
            if (tag == 0x44414548 or tag == 0x54534f50 or tag == 0x20544547 or tag == 0x4954504f) continue; // "HEAD", "POST", "GET ", "OPTI"
            if (tag == 0xeeeeeeee or tag == 0xdddddddd or tag == 0x16030102) continue;

            const second_tag = std.mem.readInt(u32, init_buf[4..8], .little);
            if (second_tag == 0) continue;
            break;
        }

        // Standard Obfuscated2: bytes 56..60 carry the protocol tag, bytes 60..62 carry DC ID
        @memcpy(init_buf[56..60], &protocol_tag);
        std.mem.writeInt(i16, init_buf[60..62], dc_id, .little);

        var enc_key: [32]u8 = undefined;
        var enc_iv: [16]u8 = undefined;
        @memcpy(&enc_key, init_buf[8..40]);
        @memcpy(&enc_iv, init_buf[40..56]);

        var rev = init_buf;
        std.mem.reverse(u8, &rev);

        var dec_key: [32]u8 = undefined;
        var dec_iv: [16]u8 = undefined;
        @memcpy(&dec_key, rev[8..40]);
        @memcpy(&dec_iv, rev[40..56]);

        var enc = aes_ctr.Stream.init(enc_key, enc_iv);
        const dec = aes_ctr.Stream.init(dec_key, dec_iv);

        var encrypted_init = init_buf;
        enc.xorStream(&encrypted_init);
        @memcpy(init_buf[56..64], encrypted_init[56..64]);

        return .{
            .enc_stream = enc,
            .dec_stream = dec,
            .init_payload = init_buf,
        };
    }
};

pub const WsTransport = struct {
    allocator: Allocator,
    mode: Mode = .obfuscated2_intermediate,
    dc_id: i16 = 2,
    init_sent: bool = false,
    obfs: ?ObfuscatedState = null,
    rx_buf: std.ArrayListUnmanaged(u8) = .empty,

    pub fn init(allocator: Allocator, mode: Mode) WsTransport {
        return .{
            .allocator = allocator,
            .mode = mode,
        };
    }

    pub fn deinit(self: *WsTransport) void {
        self.rx_buf.deinit(self.allocator);
    }

    /// Reset internal state and re-initialize Obfuscated2 keys if enabled.
    pub fn reset(self: *WsTransport, random_fn: ?*const fn ([]u8) void, dc_id: i16) void {
        self.dc_id = dc_id;
        self.init_sent = false;
        self.rx_buf.clearRetainingCapacity();

        if (random_fn) |r_fn| {
            switch (self.mode) {
                .obfuscated2_intermediate => {
                    self.obfs = ObfuscatedState.init(r_fn, [_]u8{ 0xee, 0xee, 0xee, 0xee }, dc_id);
                },
                .obfuscated2_padded => {
                    self.obfs = ObfuscatedState.init(r_fn, [_]u8{ 0xdd, 0xdd, 0xdd, 0xdd }, dc_id);
                },
                .obfuscated2_abridged => {
                    self.obfs = ObfuscatedState.init(r_fn, [_]u8{ 0xef, 0xef, 0xef, 0xef }, dc_id);
                },
                .plain_intermediate, .plain_abridged => {
                    self.obfs = null;
                },
            }
        }
    }

    pub fn setMode(self: *WsTransport, mode: Mode, random_fn: ?*const fn ([]u8) void, dc_id: i16) void {
        self.mode = mode;
        self.reset(random_fn, dc_id);
    }

    /// Returns the standalone initial handshake frame to send when WebSocket opens, if any.
    /// For Obfuscated2, this returns the 64-byte initialization payload.
    pub fn getInitFrame(self: *WsTransport) ?[]const u8 {
        if (self.init_sent) return null;
        self.init_sent = true;

        if (self.obfs) |*o| {
            return &o.init_payload;
        }

        return null;
    }

    /// Encode an MTProto payload into an outbound WebSocket frame.
    /// Applies transport envelope framing, then encrypts via Obfuscated2 AES-CTR if enabled.
    /// Returns an allocated slice owned by caller.
    pub fn encodeFrame(self: *WsTransport, payload: []const u8) ![]u8 {
        std.debug.assert(payload.len % 4 == 0);

        var inner: []u8 = undefined;

        switch (self.mode) {
            .obfuscated2_intermediate, .obfuscated2_padded, .plain_intermediate => {
                inner = try self.allocator.alloc(u8, 4 + payload.len);
                std.mem.writeInt(u32, inner[0..4], @intCast(payload.len), .little);
                @memcpy(inner[4..], payload);
            },
            .obfuscated2_abridged, .plain_abridged => {
                const words = payload.len / 4;
                var hdr_buf: [4]u8 = undefined;
                var hdr_len: usize = 0;

                if (words < 127) {
                    hdr_buf[hdr_len] = @intCast(words);
                    hdr_len += 1;
                } else {
                    hdr_buf[hdr_len] = 0x7f;
                    hdr_buf[hdr_len + 1] = @intCast(words & 0xff);
                    hdr_buf[hdr_len + 2] = @intCast((words >> 8) & 0xff);
                    hdr_buf[hdr_len + 3] = @intCast((words >> 16) & 0xff);
                    hdr_len += 4;
                }

                inner = try self.allocator.alloc(u8, hdr_len + payload.len);
                @memcpy(inner[0..hdr_len], hdr_buf[0..hdr_len]);
                @memcpy(inner[hdr_len..], payload);
            },
        }

        // Apply Obfuscated2 AES-CTR encryption stream if active
        if (self.obfs) |*o| {
            o.enc_stream.xorStream(inner);
        }

        return inner;
    }

    /// Feed incoming WebSocket binary chunk into transport.
    /// Decrypts via Obfuscated2 AES-CTR if enabled and appends to stream buffer.
    pub fn feed(self: *WsTransport, chunk: []const u8) !void {
        if (chunk.len == 0) return;

        const prev_len = self.rx_buf.items.len;
        try self.rx_buf.appendSlice(self.allocator, chunk);
        if (self.obfs) |*o| {
            o.dec_stream.xorStream(self.rx_buf.items[prev_len..]);
        }
    }

    /// Extract the next complete MTProto payload frame from the buffer, if available.
    /// The returned slice is allocated and owned by caller.
    /// Returns null if more bytes are needed.
    pub fn nextFrame(self: *WsTransport) !?[]u8 {
        const buf = self.rx_buf.items;
        if (buf.len == 0) return null;

        switch (self.mode) {
            .obfuscated2_abridged, .plain_abridged => {
                const first = buf[0];
                var header_len: usize = 1;
                var payload_len: usize = 0;

                if (first == 0x7f) {
                    if (buf.len < 4) return null; // Need 3 more bytes for length
                    header_len = 4;
                    const b1 = @as(usize, buf[1]);
                    const b2 = @as(usize, buf[2]);
                    const b3 = @as(usize, buf[3]);
                    payload_len = (b1 | (b2 << 8) | (b3 << 16)) * 4;
                } else {
                    payload_len = @as(usize, first) * 4;
                }

                const total_frame_len = header_len + payload_len;
                if (buf.len < total_frame_len) return null; // Incomplete frame

                const payload = try self.allocator.dupe(u8, buf[header_len..total_frame_len]);
                const remaining = buf.len - total_frame_len;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, self.rx_buf.items[0..remaining], self.rx_buf.items[total_frame_len..]);
                }
                self.rx_buf.shrinkRetainingCapacity(remaining);
                return payload;
            },
            .obfuscated2_intermediate, .obfuscated2_padded, .plain_intermediate => {
                if (buf.len < 4) return null;
                const payload_len = std.mem.readInt(u32, buf[0..4], .little);
                const total_frame_len = 4 + payload_len;
                if (buf.len < total_frame_len) return null;

                const payload = try self.allocator.dupe(u8, buf[4..total_frame_len]);
                const remaining = buf.len - total_frame_len;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, self.rx_buf.items[0..remaining], self.rx_buf.items[total_frame_len..]);
                }
                self.rx_buf.shrinkRetainingCapacity(remaining);
                return payload;
            },
        }
    }
};

fn testRandom(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @intCast((i * 17 + 3) & 0xff);
}

test "WsTransport Obfuscated2 handshake and packet encryption roundtrip" {
    const allocator = std.testing.allocator;
    var client_ws = WsTransport.init(allocator, .obfuscated2_intermediate);
    defer client_ws.deinit();

    client_ws.reset(testRandom, 2);

    // 1. Get 64-byte init payload
    const init_frame = client_ws.getInitFrame().?;
    try std.testing.expectEqual(@as(usize, 64), init_frame.len);

    // Simulating Server: parse 64-byte init frame
    var server_dec_key: [32]u8 = undefined;
    var server_dec_iv: [16]u8 = undefined;
    @memcpy(&server_dec_key, init_frame[8..40]);
    @memcpy(&server_dec_iv, init_frame[40..56]);
    var server_dec_stream = aes_ctr.Stream.init(server_dec_key, server_dec_iv);

    // Server consumes the 64-byte init payload in dec_stream
    var server_init_copy: [64]u8 = undefined;
    @memcpy(&server_init_copy, init_frame);
    server_dec_stream.xorStream(&server_init_copy);

    var rev: [64]u8 = undefined;
    for (init_frame, 0..) |b, i| rev[63 - i] = b;
    var server_enc_key: [32]u8 = undefined;
    var server_enc_iv: [16]u8 = undefined;
    @memcpy(&server_enc_key, rev[8..40]);
    @memcpy(&server_enc_iv, rev[40..56]);
    var server_enc_stream = aes_ctr.Stream.init(server_enc_key, server_enc_iv);

    // 2. Client encodes MTProto packet
    const payload = [_]u8{ 10, 20, 30, 40, 50, 60, 70, 80 };
    const enc_frame = try client_ws.encodeFrame(&payload);
    defer allocator.free(enc_frame);

    // 3. Server decrypts received frame
    var server_received = try allocator.dupe(u8, enc_frame);
    defer allocator.free(server_received);
    server_dec_stream.xorStream(server_received);

    // Server should receive [4-byte len = 8][payload (8 bytes)]
    const server_payload_len = std.mem.readInt(u32, server_received[0..4], .little);
    try std.testing.expectEqual(@as(u32, 8), server_payload_len);
    try std.testing.expectEqualSlices(u8, &payload, server_received[4..]);

    // 4. Server responds with response frame
    const resp_payload = [_]u8{ 99, 88, 77, 66, 55, 44, 33, 22 };
    var server_resp_plain: [4 + resp_payload.len]u8 = undefined;
    std.mem.writeInt(u32, server_resp_plain[0..4], resp_payload.len, .little);
    @memcpy(server_resp_plain[4..], &resp_payload);

    var server_resp_encrypted = server_resp_plain;
    server_enc_stream.xorStream(&server_resp_encrypted);

    // 5. Client feeds server response
    try client_ws.feed(&server_resp_encrypted);
    const client_decoded = (try client_ws.nextFrame()).?;
    defer allocator.free(client_decoded);

    try std.testing.expectEqualSlices(u8, &resp_payload, client_decoded);
    try std.testing.expect((try client_ws.nextFrame()) == null);
}
