const std = @import("std");
const aes = std.crypto.core.aes;

/// Streaming AES-256-CTR cipher maintaining state across arbitrary chunk sizes.
pub const Stream = struct {
    ctx: aes.AesEncryptCtx(aes.Aes256),
    iv: [16]u8,
    keystream: [16]u8 = undefined,
    ks_pos: usize = 16,

    pub fn init(key: [32]u8, iv: [16]u8) Stream {
        return .{
            .ctx = aes.AesEncryptCtx(aes.Aes256).init(key),
            .iv = iv,
            .ks_pos = 16,
        };
    }

    inline fn nextBlock(self: *Stream) void {
        self.ctx.encrypt(&self.keystream, &self.iv);
        const ctr = std.mem.readInt(u128, &self.iv, .big);
        std.mem.writeInt(u128, &self.iv, ctr +% 1, .big);
        self.ks_pos = 0;
    }

    pub fn xorStream(self: *Stream, data: []u8) void {
        var offset: usize = 0;

        // 1. Consume leftover keystream bytes from previous block
        if (self.ks_pos < 16) {
            const avail = 16 - self.ks_pos;
            const take = @min(avail, data.len);
            for (data[0..take], self.keystream[self.ks_pos..][0..take]) |*d, k| d.* ^= k;
            self.ks_pos += take;
            offset += take;
        }

        // 2. Process full 16-byte blocks
        while (offset + 16 <= data.len) : (offset += 16) {
            self.ctx.encrypt(&self.keystream, &self.iv);
            const ctr = std.mem.readInt(u128, &self.iv, .big);
            std.mem.writeInt(u128, &self.iv, ctr +% 1, .big);
            for (data[offset..][0..16], self.keystream) |*d, k| d.* ^= k;
        }

        // 3. Process remaining tail bytes (< 16)
        if (offset < data.len) {
            self.nextBlock();
            const rem = data.len - offset;
            for (data[offset..], self.keystream[0..rem]) |*d, k| d.* ^= k;
            self.ks_pos = rem;
        }
    }
};

pub fn decrypt(key: [32]u8, base_iv: [16]u8, data: []u8, file_offset: u64) void {
    const ctx = aes.AesEncryptCtx(aes.Aes256).init(key);

    var counter: [16]u8 = base_iv;
    const base_ctr = std.mem.readInt(u32, counter[12..16], .big);
    std.mem.writeInt(u32, counter[12..16], base_ctr +% @as(u32, @intCast(file_offset / 16)), .big);

    var i: usize = 0;
    while (i + 16 <= data.len) : (i += 16) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &counter);
        for (data[i..][0..16], &ks) |*d, k| d.* ^= k;
        const c = std.mem.readInt(u32, counter[12..16], .big);
        std.mem.writeInt(u32, counter[12..16], c +% 1, .big);
    }
    if (i < data.len) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &counter);
        for (data[i..], ks[0 .. data.len - i]) |*d, k| d.* ^= k;
    }
}

test "aes_ctr: self-inverse" {
    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    for (&iv, 0..) |*b, i| b.* = @intCast(i + 32);
    var data = [_]u8{0xab} ** 64;
    const original = data;
    decrypt(key, iv, &data, 0);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));
    decrypt(key, iv, &data, 0);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "aes_ctr: offset continuity" {
    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    for (&iv, 0..) |*b, i| b.* = @intCast(i + 32);
    var full = [_]u8{0xab} ** 64;
    decrypt(key, iv, &full, 0);
    var first = [_]u8{0xab} ** 32;
    var second = [_]u8{0xab} ** 32;
    decrypt(key, iv, &first, 0);
    decrypt(key, iv, &second, 32);
    try std.testing.expectEqualSlices(u8, full[0..32], &first);
    try std.testing.expectEqualSlices(u8, full[32..64], &second);
}

test "aes_ctr.Stream: stream encryption and decryption roundtrip across arbitrary chunk sizes" {
    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    for (&iv, 0..) |*b, i| b.* = @intCast(i + 32);

    var enc = Stream.init(key, iv);
    var dec = Stream.init(key, iv);

    const plaintext = "The quick brown fox jumps over the lazy dog! MTProto 2.0 WebAssembly Telegram client.";
    var buf: [plaintext.len]u8 = undefined;
    @memcpy(&buf, plaintext);

    // Encrypt in uneven chunk slices (e.g. 5 bytes, then 17 bytes, then remaining)
    enc.xorStream(buf[0..5]);
    enc.xorStream(buf[5..22]);
    enc.xorStream(buf[22..]);

    try std.testing.expect(!std.mem.eql(u8, &buf, plaintext));

    // Decrypt in different chunk slices (e.g. 3 bytes, then 30 bytes, then remaining)
    dec.xorStream(buf[0..3]);
    dec.xorStream(buf[3..33]);
    dec.xorStream(buf[33..]);

    try std.testing.expectEqualStrings(plaintext, &buf);
}

test "aes_ctr.Stream: 1-byte chunks and exact block boundaries" {
    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    for (&iv, 0..) |*b, i| b.* = @intCast(i + 1);

    var enc = Stream.init(key, iv);
    var dec = Stream.init(key, iv);

    var buf: [64]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast(i);
    const orig = buf;

    // Encrypt byte-by-byte
    for (&buf) |*b| enc.xorStream((@as(*[1]u8, b))[0..]);
    try std.testing.expect(!std.mem.eql(u8, &buf, &orig));

    // Decrypt in exact 16-byte blocks
    dec.xorStream(buf[0..16]);
    dec.xorStream(buf[16..32]);
    dec.xorStream(buf[32..48]);
    dec.xorStream(buf[48..64]);
    try std.testing.expectEqualSlices(u8, &orig, &buf);
}
