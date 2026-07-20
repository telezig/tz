const std = @import("std");
const Allocator = std.mem.Allocator;
const Managed = std.math.big.int.Managed;
const Limb = std.math.big.Limb;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

pub const Answer = struct {
    A: [256]u8,
    M1: [32]u8,
};

/// Compute Telegram SRP answer for PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow.
/// salt1, salt2, p are the algo fields; B is srp_B from account.Password.
pub fn compute(
    allocator: Allocator,
    io: std.Io,
    salt1: []const u8,
    salt2: []const u8,
    g: i32,
    p: []const u8,
    B: []const u8,
    password: []const u8,
) !Answer {
    var a_bytes: [256]u8 = undefined;
    io.random(&a_bytes);
    return computeWithA(allocator, salt1, salt2, g, p, B, password, &a_bytes);
}

/// Same as compute() but with deterministic `a_bytes` for testing.
pub fn computeWithA(
    allocator: Allocator,
    salt1: []const u8,
    salt2: []const u8,
    g: i32,
    p: []const u8,
    B: []const u8,
    password: []const u8,
    a_bytes: *const [256]u8,
) !Answer {
    // g as 256-byte big-endian
    var g_bytes: [256]u8 = std.mem.zeroes([256]u8);
    std.mem.writeInt(u32, g_bytes[252..][0..4], @intCast(g), .big);

    // PH1 = SH(SH(password, salt1), salt2)
    const ph1 = sh(&sh(password, salt1), salt2);

    // PH2 = SH(PBKDF2(PH1, salt1, 100000, 64), salt2)
    var pbkdf2_buf: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&pbkdf2_buf, &ph1, salt1, 100000, HmacSha512);
    const ph2 = sh(&pbkdf2_buf, salt2);

    // x = PH2
    const x_bytes = ph2;

    // bigint representations
    var p_m = try bigFromBE(allocator, p);
    defer p_m.deinit();
    var g_m = try bigFromBE(allocator, &g_bytes);
    defer g_m.deinit();
    var a_m = try bigFromBE(allocator, a_bytes);
    defer a_m.deinit();
    var x_m = try bigFromBE(allocator, &x_bytes);
    defer x_m.deinit();
    var B_m = try bigFromBE(allocator, B);
    defer B_m.deinit();

    // A = g^a mod p
    var A_m = try Managed.init(allocator);
    defer A_m.deinit();
    try powMod(allocator, &A_m, &g_m, &a_m, &p_m);
    var A_bytes: [256]u8 = undefined;
    A_m.toConst().writeTwosComplement(&A_bytes, .big);

    // k = sha256(p ++ g_padded)
    const k_bytes = h(.{ p, &g_bytes });
    var k_m = try bigFromBE(allocator, &k_bytes);
    defer k_m.deinit();

    // u = sha256(A ++ B)
    const u_bytes = h(.{ &A_bytes, B });
    var u_m = try bigFromBE(allocator, &u_bytes);
    defer u_m.deinit();

    // g^x mod p
    var gx_m = try Managed.init(allocator);
    defer gx_m.deinit();
    try powMod(allocator, &gx_m, &g_m, &x_m, &p_m);

    // k_gx = k * g^x mod p
    var q = try Managed.init(allocator);
    defer q.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var k_gx = try Managed.init(allocator);
    defer k_gx.deinit();
    try k_gx.mul(&k_m, &gx_m);
    try Managed.divFloor(&q, &rem, &k_gx, &p_m);
    k_gx.swap(&rem);

    // d = (B - k_gx) mod p
    var d = try Managed.init(allocator);
    defer d.deinit();
    var tmp = try Managed.init(allocator);
    defer tmp.deinit();
    try d.sub(&B_m, &k_gx);
    if (!d.isPositive()) {
        try tmp.add(&d, &p_m);
        d.swap(&tmp);
    }

    // exp = a + u*x
    var ux = try Managed.init(allocator);
    defer ux.deinit();
    try ux.mul(&u_m, &x_m);
    var exp_bi = try Managed.init(allocator);
    defer exp_bi.deinit();
    try exp_bi.add(&a_m, &ux);

    // S = d^exp mod p
    var S_m = try Managed.init(allocator);
    defer S_m.deinit();
    try powMod(allocator, &S_m, &d, &exp_bi, &p_m);
    var S_bytes: [256]u8 = undefined;
    S_m.toConst().writeTwosComplement(&S_bytes, .big);

    // K = sha256(S)
    const K = h(.{&S_bytes});

    // M1 = sha256(xor(sha256(p), sha256(g_padded)) ++ sha256(salt1) ++ sha256(salt2) ++ A ++ B ++ K)
    const hp = h(.{p});
    const hg = h(.{&g_bytes});
    var xor_hpg: [32]u8 = undefined;
    for (&xor_hpg, hp, hg) |*out, a_byte, b_byte| out.* = a_byte ^ b_byte;

    return .{
        .A = A_bytes,
        .M1 = h(.{ &xor_hpg, &h(.{salt1}), &h(.{salt2}), &A_bytes, B, &K }),
    };
}

// sha256(parts...)
fn h(parts: anytype) [32]u8 {
    var hasher = Sha256.init(.{});
    inline for (parts) |p| hasher.update(p);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

// SH(data, salt) = sha256(salt ++ data ++ salt)
fn sh(data: []const u8, salt: []const u8) [32]u8 {
    return h(.{ salt, data, salt });
}

fn bigFromBE(allocator: Allocator, bytes: []const u8) !Managed {
    const limb_count = bytes.len / @sizeOf(Limb) + 2;
    var m = try Managed.initCapacity(allocator, limb_count);
    var mut = m.toMutable();
    mut.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    m.setMetadata(mut.positive, mut.len);
    return m;
}

// result = base^exp mod mod
fn powMod(allocator: Allocator, result: *Managed, base: *const Managed, exp: *const Managed, mod: *const Managed) !void {
    try result.set(1);

    var b = try base.clone();
    defer b.deinit();
    var q = try Managed.init(allocator);
    defer q.deinit();
    var rem = try Managed.init(allocator);
    defer rem.deinit();
    var tmp = try Managed.init(allocator);
    defer tmp.deinit();

    // b = base mod p
    try Managed.divFloor(&q, &rem, &b, mod);
    b.swap(&rem);

    const limb_bits = @bitSizeOf(Limb);
    const nbits = exp.bitCountAbs();
    for (0..nbits) |i| {
        const limb_idx = i / limb_bits;
        const bit_shift: std.math.Log2Int(Limb) = @intCast(i % limb_bits);
        const bit: u1 = @truncate(exp.limbs[limb_idx] >> bit_shift);

        if (bit != 0) {
            try tmp.mul(result, &b);
            result.swap(&tmp);
            try Managed.divFloor(&q, &tmp, result, mod);
            result.swap(&tmp);
        }

        try tmp.sqr(&b);
        b.swap(&tmp);
        try Managed.divFloor(&q, &tmp, &b, mod);
        b.swap(&tmp);
    }
}

test "srp: matches gotd reference" {
    const password = "123123";
    const B_hex = "9C52401A6A8084EC82F01C3725D3FB448BD2F0C909F9D97726EAC4B7A74172D9" ++
        "52F02466BE6734FA274D2B7429E27397F10372D66B400B80A5C5AE3F28B17BF3" ++
        "105D7A2D2A885998CDC2DEFC208AEC217AB58859A9ABC2374AD93DC285F4B3FB" ++
        "CAFF4143D7888F2425BD2FB711B25609CEB21757D935B1EF2F042173AD0CE2FE" ++
        "0E474DAC53914BD25A8A9AED4AEA8953D55CB88621DB37B871EA0D04393AC098" ++
        "7F68094CCC9DE8239251375D8FFFD263316CD528C097B7BC9FB919FBEDB76C52" ++
        "5DF3413C374EE076D97A1E6D352BB7CC80FD13651B04B32E2E48C5268150842C" ++
        "FD07CF855958B1B5EA9C36FDAD697FE3AEC8DCC6B1EFEC36874AF226204676CF";
    const salt1_hex =
        "4D11FB6BEC38F9D2546BB0F61E4F1C99A1BC0DB8F0D5F35B1291B37B213123D7ED48F3C6794D495B";
    const salt2_hex = "A1B181AAFE88188680AE32860D60BB01";
    const p_hex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" ++
        "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37" ++
        "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64" ++
        "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4" ++
        "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754" ++
        "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4" ++
        "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F" ++
        "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B";

    var B: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&B, B_hex);
    var salt1: [40]u8 = undefined;
    _ = try std.fmt.hexToBytes(&salt1, salt1_hex);
    var salt2: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&salt2, salt2_hex);
    var p: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p, p_hex);

    // deterministic a = 1 (256-byte big-endian), matching Go test: setByte(256, 1)
    var a_bytes: [256]u8 = std.mem.zeroes([256]u8);
    std.mem.writeInt(u32, a_bytes[252..][0..4], 1, .big);

    const answer = try computeWithA(
        std.testing.allocator,
        &salt1,
        &salt2,
        3,
        &p,
        &B,
        password,
        &a_bytes,
    );

    // expected A = 3 (256-byte big-endian), matching Go: setByte(256, 3)
    var expected_A: [256]u8 = std.mem.zeroes([256]u8);
    std.mem.writeInt(u32, expected_A[252..][0..4], 3, .big);
    try std.testing.expectEqualSlices(u8, &expected_A, &answer.A);

    var expected_M1: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_M1, "999DF906BDA2C6CBB52F503406EBA2D0D0503ACE0CC302C38F13EE5010AD4051");
    try std.testing.expectEqualSlices(u8, &expected_M1, &answer.M1);
}
