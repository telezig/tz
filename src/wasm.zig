const std = @import("std");
const tz = @import("tz");
const sha = tz.crypto.sha;
const rsa = tz.crypto.rsa;
const dh = tz.crypto.dh;
const aes_ige = tz.crypto.aes_ige;
const Session = tz.Session;
const WsTransport = tz.ws.WsTransport;
const codec = @import("codec");
const types = @import("types");
const functions = @import("functions");
const ser = codec.serialize;
const de = codec.deserialize;

// --- JS Imports ---
extern fn js_log(ptr: [*]const u8, len: usize) void;
extern fn js_on_status(ptr: [*]const u8, len: usize) void;
extern fn js_on_qr(ptr: [*]const u8, len: usize) void;
extern fn js_on_login_success(user_id: i64) void;
extern fn js_ws_send(ptr: [*]const u8, len: usize) void;
extern fn js_random(ptr: [*]u8, len: usize) void;
extern fn js_now_sec() u32;
extern fn js_now_ms_part() u32;

fn log(msg: []const u8) void {
    js_log(msg.ptr, msg.len);
}

fn setStatus(msg: []const u8) void {
    js_on_status(msg.ptr, msg.len);
}

// Memory allocator
const allocator = std.heap.wasm_allocator;

export fn tz_alloc(len: usize) ?[*]u8 {
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

export fn tz_free(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}

// Random & Time helpers for WASM
fn fillRandom(buf: []u8) void {
    js_random(buf.ptr, buf.len);
}

fn wasmNowMs() i64 {
    // ms since epoch: sec*1000 + ms_part
    return @as(i64, @intCast(js_now_sec())) * 1000 + @as(i64, @intCast(js_now_ms_part()));
}

/// The unified Session's platform entropy for wasm: Web Crypto + Date.now.
const wasm_entropy = Session.Entropy{ .js = .{
    .random = struct {
        fn f(buf: []u8) void {
            fillRandom(buf);
        }
    }.f,
    .now_ms = struct {
        fn f() i64 {
            return wasmNowMs();
        }
    }.f,
} };

// Telegram Server RSA Public Key (Standard Telegram DC Key)
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

// GCD & Pollard's rho for factorPQ
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

fn randU64() u64 {
    var buf: [8]u8 = undefined;
    fillRandom(&buf);
    return @bitCast(buf);
}

fn factorPQ(pq: u64) struct { p: u32, q: u32 } {
    if (pq % 2 == 0) return .{ .p = 2, .q = @intCast(pq / 2) };
    var x: u64 = randU64() % (pq - 2) + 2;
    var y = x;
    const c: u64 = randU64() % (pq - 1) + 1;
    var d: u64 = 1;
    while (d == 1) {
        x = @intCast((@as(u128, x) * @as(u128, x) + @as(u128, c)) % @as(u128, pq));
        y = @intCast((@as(u128, y) * @as(u128, y) + @as(u128, c)) % @as(u128, pq));
        y = @intCast((@as(u128, y) * @as(u128, y) + @as(u128, c)) % @as(u128, pq));
        d = gcd(if (x > y) x - y else y - x, pq);
    }
    if (d == pq) return factorPQ(pq);
    const p: u32 = @intCast(d);
    const q: u32 = @intCast(pq / d);
    return if (p < q) .{ .p = p, .q = q } else .{ .p = q, .q = p };
}

// Global Transport
var ws_transport = WsTransport.init(allocator, .obfuscated2_intermediate);
var current_dc_id: i16 = 2;
var last_plain_msg_id: i64 = 0;

fn generateMsgId(sec: i64, ms_part: u32, last_id: *i64) i64 {
    const nano: u64 = @as(u64, ms_part) * 1_000_000;
    const lower: u64 = ((nano << 32) / 1_000_000_000) & ~@as(u64, 3);
    var id: i64 = @bitCast((@as(u64, @intCast(sec)) << 32) | lower);
    if (id <= last_id.*) id = last_id.* + 4;
    last_id.* = id;
    return id;
}

fn nextPlainMsgId() i64 {
    const sec: i64 = @intCast(js_now_sec());
    const ms_part = js_now_ms_part();
    return generateMsgId(sec, ms_part, &last_plain_msg_id);
}

export fn tz_set_dc_id(dc: i16) void {
    current_dc_id = dc;
    ws_transport.reset(fillRandom, current_dc_id);
}

export fn tz_set_transport_mode(mode_val: u8) void {
    switch (mode_val) {
        0 => {
            ws_transport.setMode(.obfuscated2_intermediate, fillRandom, current_dc_id);
            log("Transport: Obfuscated2 (AES-256-CTR) + Intermediate (Standard Web)");
        },
        1 => {
            ws_transport.setMode(.obfuscated2_padded, fillRandom, current_dc_id);
            log("Transport: Obfuscated2 (AES-256-CTR) + Padded Intermediate (0xdddddddd)");
        },
        2 => {
            ws_transport.setMode(.obfuscated2_abridged, fillRandom, current_dc_id);
            log("Transport: Obfuscated2 (AES-256-CTR) + Abridged (0xef)");
        },
        3 => {
            ws_transport.setMode(.plain_intermediate, null, current_dc_id);
            log("Transport: Plain Intermediate (Unobfuscated)");
        },
        4 => {
            ws_transport.setMode(.plain_abridged, null, current_dc_id);
            log("Transport: Plain Abridged (Unobfuscated)");
        },
        else => {},
    }
}

fn sendPlainMsg(payload: []const u8) !void {
    const frame_len = 20 + payload.len;
    const padded = ((frame_len + 3) / 4) * 4;
    var frame_buf: [1024]u8 = undefined;
    const frame = if (padded <= frame_buf.len) frame_buf[0..padded] else try allocator.alloc(u8, padded);
    defer if (padded > frame_buf.len) allocator.free(frame);
    @memset(frame, 0);

    // auth_key_id = 0 for plain message
    std.mem.writeInt(i64, frame[0..8], 0, .little);
    const msg_id = nextPlainMsgId();
    std.mem.writeInt(i64, frame[8..16], msg_id, .little);
    std.mem.writeInt(u32, frame[16..20], @intCast(payload.len), .little);
    @memcpy(frame[20..][0..payload.len], payload);

    const encoded = try ws_transport.encodeFrame(frame);
    defer allocator.free(encoded);
    js_ws_send(encoded.ptr, encoded.len);
}

fn sendEncryptedMsg(ciphertext: []const u8) !void {
    const encoded = try ws_transport.encodeFrame(ciphertext);
    defer allocator.free(encoded);
    js_ws_send(encoded.ptr, encoded.len);
}

// Session State for Encrypted Messaging

// Global Client State
const Stage = enum {
    idle,
    req_pq_sent,
    req_dh_sent,
    set_client_dh_sent,
    ready,
};

var stage: Stage = .idle;
var api_id: i32 = 0;
var api_hash_buf: [64]u8 = undefined;
var api_hash_len: usize = 0;

var nonce: [16]u8 = undefined;
var server_nonce: [16]u8 = undefined;
var new_nonce: [32]u8 = undefined;
var tmp_key: [32]u8 = undefined;
var tmp_iv: [32]u8 = undefined;

var session: ?Session = null;

export fn tz_init(app_id: i32, hash_ptr: [*]const u8, hash_len: usize) void {
    api_id = app_id;
    api_hash_len = @min(hash_len, api_hash_buf.len);
    @memcpy(api_hash_buf[0..api_hash_len], hash_ptr[0..api_hash_len]);
    stage = .idle;
    ws_transport.reset(fillRandom, current_dc_id);
    log("tz WebAssembly client initialized with Obfuscated2 transport");
    setStatus("Ready to connect");
}

export fn tz_ws_open() void {
    ws_transport.reset(fillRandom, current_dc_id);
    if (ws_transport.getInitFrame()) |init_frame| {
        js_ws_send(init_frame.ptr, init_frame.len);
    }
    setStatus("WebSocket opened, starting Obfuscated2 DH key exchange...");
    startDhHandshake() catch {
        log("DH handshake start failed");
        setStatus("DH handshake failed");
    };
}

fn startDhHandshake() !void {
    fillRandom(&nonce);
    var req_buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    try w.writeInt(u32, 0xbe7e8ef1, .little); // req_pq_multi
    try w.writeAll(&nonce);

    try sendPlainMsg(w.buffered());
    stage = .req_pq_sent;
    setStatus("req_pq_multi sent...");
}

export fn tz_on_ws_chunk(chunk_ptr: [*]const u8, chunk_len: usize) void {
    const chunk = chunk_ptr[0..chunk_len];
    ws_transport.feed(chunk) catch {
        log("ws_transport.feed error");
        return;
    };

    while (ws_transport.nextFrame() catch null) |frame| {
        defer allocator.free(frame);
        handleMtprotoFrame(frame) catch {
            log("Error handling MTProto frame");
        };
    }
}

fn handleMtprotoFrame(frame: []const u8) !void {
    // Handle unencrypted frames (auth_key_id == 0)
    if (frame.len >= 20 and std.mem.readInt(i64, frame[0..8], .little) == 0) {
        const payload_len = std.mem.readInt(u32, frame[16..20], .little);
        if (20 + payload_len > frame.len) return;
        const payload = frame[20 .. 20 + payload_len];
        if (payload.len < 4) return;
        const cid = std.mem.readInt(u32, payload[0..4], .little);

        switch (stage) {
            .req_pq_sent => {
                if (cid != 0x05162463) return; // resPQ
                setStatus("resPQ received, factoring PQ & preparing RSA payload...");
                var r: std.Io.Reader = .fixed(payload[4..]);
                var nonce_echo: [16]u8 = undefined;
                try r.readSliceAll(&nonce_echo);
                try r.readSliceAll(&server_nonce);
                const pq_bytes = try de.bytes(&r, allocator);
                defer allocator.free(pq_bytes);
                var pq: u64 = 0;
                for (pq_bytes) |b| pq = pq * 256 + b;

                const factors = factorPQ(pq);
                var p_bytes: [4]u8 = undefined;
                var q_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &p_bytes, factors.p, .big);
                std.mem.writeInt(u32, &q_bytes, factors.q, .big);
                fillRandom(&new_nonce);

                var inner_buf: [256]u8 = undefined;
                var iw: std.Io.Writer = .fixed(&inner_buf);
                try iw.writeInt(u32, 0x83c95aec, .little);
                try ser.bytes(&iw, pq_bytes);
                try ser.bytes(&iw, &p_bytes);
                try ser.bytes(&iw, &q_bytes);
                try iw.writeAll(&nonce);
                try iw.writeAll(&server_nonce);
                try iw.writeAll(&new_nonce);

                const inner_data = iw.buffered();
                const inner_hash = sha.sha1(inner_data);
                var rsa_payload: [255]u8 = undefined;
                @memcpy(rsa_payload[0..20], &inner_hash);
                const copy_len = @min(inner_data.len, 235);
                @memcpy(rsa_payload[20..][0..copy_len], inner_data[0..copy_len]);
                fillRandom(rsa_payload[20 + copy_len ..]);

                var encrypted_data: [256]u8 = undefined;
                try rsa.rsaEncrypt(&encrypted_data, &rsa_payload, serverKeyN[0..256], allocator);

                var req2_buf: [512]u8 = undefined;
                var w2: std.Io.Writer = .fixed(&req2_buf);
                try w2.writeInt(u32, 0xd712e4be, .little); // req_DH_params
                try w2.writeAll(&nonce);
                try w2.writeAll(&server_nonce);
                try ser.bytes(&w2, &p_bytes);
                try ser.bytes(&w2, &q_bytes);
                try w2.writeInt(i64, serverKeyFp, .little);
                try ser.bytes(&w2, &encrypted_data);

                try sendPlainMsg(w2.buffered());
                stage = .req_dh_sent;
                setStatus("req_DH_params sent...");
            },
            .req_dh_sent => {
                if (cid != 0xd0e8075c) return; // server_DH_params_ok
                setStatus("server_DH_params_ok received, computing Diffie-Hellman shared key...");
                var dhr: std.Io.Reader = .fixed(payload[4..]);
                var skip16: [16]u8 = undefined;
                try dhr.readSliceAll(&skip16);
                try dhr.readSliceAll(&skip16);
                const enc_answer = try de.bytes(&dhr, allocator);
                defer allocator.free(enc_answer);

                const sha1_ns = sha.sha1Cat(&.{ &new_nonce, &server_nonce });
                const sha1_sn = sha.sha1Cat(&.{ &server_nonce, &new_nonce });
                const sha1_nn = sha.sha1Cat(&.{ &new_nonce, &new_nonce });
                @memcpy(tmp_key[0..20], &sha1_ns);
                @memcpy(tmp_key[20..32], sha1_sn[0..12]);
                @memcpy(tmp_iv[0..8], sha1_sn[12..20]);
                @memcpy(tmp_iv[8..28], &sha1_nn);
                @memcpy(tmp_iv[28..32], new_nonce[0..4]);

                const answer_buf = try allocator.dupe(u8, enc_answer);
                defer allocator.free(answer_buf);
                aes_ige.decrypt(tmp_key, tmp_iv, answer_buf);

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

                var dh_prime: [256]u8 = undefined;
                var g_a: [256]u8 = undefined;
                @memset(&dh_prime, 0);
                @memset(&g_a, 0);
                if (dh_prime_bytes.len <= 256) @memcpy(dh_prime[256 - dh_prime_bytes.len ..], dh_prime_bytes);
                if (g_a_bytes.len <= 256) @memcpy(g_a[256 - g_a_bytes.len ..], g_a_bytes);
                var b_bytes: [256]u8 = undefined;
                fillRandom(&b_bytes);

                const dh_result = try dh.compute(.{ .dh_prime = dh_prime, .g = dh_g }, &g_a, &b_bytes, allocator);

                var ci_data_buf: [320]u8 = undefined;
                var ciw: std.Io.Writer = .fixed(&ci_data_buf);
                try ciw.writeInt(u32, 0x6643b654, .little);
                try ciw.writeAll(&nonce);
                try ciw.writeAll(&server_nonce);
                try ciw.writeInt(i64, 0, .little);
                try ser.bytes(&ciw, &dh_result.g_b);
                const ci_data = ciw.buffered();
                const ci_hash = sha.sha1(ci_data);

                const ci_total = 20 + ci_data.len;
                const ci_padded_len = ((ci_total + 15) / 16) * 16;
                var ci_padded_buf: [352]u8 = undefined;
                const ci_padded = ci_padded_buf[0..ci_padded_len];
                @memcpy(ci_padded[0..20], &ci_hash);
                @memcpy(ci_padded[20..][0..ci_data.len], ci_data);
                fillRandom(ci_padded[20 + ci_data.len ..]);
                aes_ige.encrypt(tmp_key, tmp_iv, ci_padded);

                var set_buf: [512]u8 = undefined;
                var sw: std.Io.Writer = .fixed(&set_buf);
                try sw.writeInt(u32, 0xf5045f1f, .little); // set_client_DH_params
                try sw.writeAll(&nonce);
                try sw.writeAll(&server_nonce);
                try ser.bytes(&sw, ci_padded);

                const auth_key_hash = sha.sha1(&dh_result.secret);
                var auth_key_id: i64 = undefined;
                @memcpy(std.mem.asBytes(&auth_key_id), auth_key_hash[12..20]);

                var server_salt: i64 = undefined;
                for (std.mem.asBytes(&server_salt), new_nonce[0..8], server_nonce[0..8]) |*o, a, b| o.* = a ^ b;

                const local_s: i32 = @intCast(js_now_sec());
                const time_offset: i64 = @intCast(server_time - local_s);

                if (session) |*s| s.deinit(allocator);
                session = Session.init(dh_result.secret, auth_key_id, server_salt, wasm_entropy);
                session.?.time_offset = time_offset;

                try sendPlainMsg(sw.buffered());
                stage = .set_client_dh_sent;
                setStatus("set_client_DH_params sent...");
            },
            .set_client_dh_sent => {
                if (cid != 0x3bcbf734) return; // dh_gen_ok
                stage = .ready;
                setStatus("DH Key Exchange complete! Auth Key established. Exporting Login Token...");
                log("DH Key Exchange SUCCESS! Ready for MTProto 2.0 Encrypted RPCs.");
                try exportLoginQr();
            },
            else => {},
        }
        return;
    }

    // Handle encrypted frames
    if (session) |*s| {
        const decrypted = s.decrypt(frame, allocator) catch {
            log("Decrypt error on incoming frame");
            return;
        };
        // payload borrows session.decrypt_scratch — consumed synchronously here.
        try handleEncryptedPayload(decrypted.payload);
    }
}

fn wrapInit(alloc_inst: std.mem.Allocator, app_id: i32, query_bytes: []const u8) ![]u8 {
    var hdr: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&hdr);
    try w.writeInt(u32, functions.InvokeWithLayer.cid, .little);
    try w.writeInt(i32, functions.layer, .little);
    try w.writeInt(u32, functions.InitConnection.cid, .little);
    try w.writeInt(i32, 0, .little);
    try ser.int(&w, app_id);
    try ser.string(&w, "tz-web");
    try ser.string(&w, "Browser/WASM");
    try ser.string(&w, "0.1");
    try ser.string(&w, "en");
    try ser.string(&w, "");
    try ser.string(&w, "en");
    const h = w.buffered();
    const out = try alloc_inst.alloc(u8, h.len + query_bytes.len);
    @memcpy(out[0..h.len], h);
    @memcpy(out[h.len..], query_bytes);
    return out;
}

export fn tz_export_login_qr() void {
    exportLoginQr() catch {
        log("exportLoginQr failed");
    };
}

fn exportLoginQr() !void {
    if (session == null or stage != .ready) return;
    const req = functions.auth.ExportLoginToken{
        .api_id = api_id,
        .api_hash = api_hash_buf[0..api_hash_len],
        .except_ids = &.{},
    };
    const req_bytes = try codec.encodeAlloc(req, allocator);
    defer allocator.free(req_bytes);

    const wrapped = try wrapInit(allocator, api_id, req_bytes);
    defer allocator.free(wrapped);

    const enc = try session.?.encrypt(wrapped, allocator, true);
    defer allocator.free(enc.data);

    try sendEncryptedMsg(enc.data);
    setStatus("auth.exportLoginToken sent, awaiting login token...");
}

fn handleEncryptedPayload(payload: []const u8) !void {
    if (payload.len < 4) return;
    const cid = std.mem.readInt(u32, payload[0..4], .little);

    // If rpc_result (0xf35c6d01)
    if (cid == 0xf35c6d01 and payload.len >= 12) {
        const inner_payload = payload[12..];
        if (inner_payload.len < 4) return;
        const inner_cid = std.mem.readInt(u32, inner_payload[0..4], .little);

        // rpc_error (0x2144ca19)
        if (inner_cid == tz.RpcError.cid) {
            const err = tz.RpcError.parse(inner_payload);
            var err_buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&err_buf, "RPC Error {d}: {s}", .{ err.code, err.name() }) catch "RPC Error";
            log(msg);
            setStatus(msg);
            return;
        }

        // auth.loginToken (0x629f1980)
        if (inner_cid == 0x629f1980) {
            var r: std.Io.Reader = .fixed(inner_payload[4..]);
            const expires = try r.takeInt(i32, .little);
            _ = expires;
            const token = try de.bytes(&r, allocator);
            defer allocator.free(token);

            const prefix = "tg://login?token=";
            const enc = &std.base64.url_safe_no_pad.Encoder;
            const buf = try allocator.alloc(u8, prefix.len + enc.calcSize(token.len));
            defer allocator.free(buf);
            @memcpy(buf[0..prefix.len], prefix);
            _ = enc.encode(buf[prefix.len..], token);

            log("Login QR Code URL generated!");
            setStatus("Scan QR Code with Telegram App (Settings -> Devices -> Link Desktop Device)");
            js_on_qr(buf.ptr, buf.len);
            return;
        }

        // auth.loginTokenSuccess (0x390d5f5e)
        if (inner_cid == 0x390d5f5e) {
            setStatus("Login Successful! Authorized!");
            log("auth.loginTokenSuccess received! Authenticated!");
            js_on_login_success(1);
            return;
        }
    }
}
