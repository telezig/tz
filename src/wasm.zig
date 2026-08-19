const std = @import("std");
const tz = @import("tz");
const Session = tz.Session;
const AuthKey = tz.auth_key.AuthKey;
const WsTransport = tz.ws.WsTransport;
const codec = @import("codec");
const types = @import("types");
const unions = @import("unions");
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
/// Message persistence bridge: called with each incoming new message so the
/// host can store it (e.g. into the OPFS sqlite store). ptr/len reference the
/// UTF-8 message text in wasm memory.
extern fn js_on_message(peer_id: i64, from_id: i64, date: i32, msg_id: i64, out: bool, text_ptr: [*]const u8, text_len: usize) void;
/// DC migration: the host should reconnect to the WebSocket endpoint for this
/// dc_id (auth key is per-DC, so a fresh DH handshake happens automatically).
extern fn js_on_migrate(dc_id: u8) void;
/// Auth key established — host should persist the session (exported via
/// tz_export_session) so a future page load can skip the DH handshake.
extern fn js_on_session_ready() void;

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
// Global Transport
var ws_transport = WsTransport.init(allocator, .obfuscated2_intermediate);
var current_dc_id: i16 = 2;
var last_plain_msg_id: i64 = 0;

// Sans-I/O DH handshake state machine (shared with native auth_key).
var ak: AuthKey = undefined;
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
    ready,
};

var stage: Stage = .idle;
var api_id: i32 = 0;
var api_hash_buf: [64]u8 = undefined;
var api_hash_len: usize = 0;
var bot_token_buf: [128]u8 = undefined;
var bot_token_len: usize = 0;

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

export fn tz_set_bot_token(token_ptr: [*]const u8, token_len: usize) void {
    bot_token_len = @min(token_len, bot_token_buf.len);
    @memcpy(bot_token_buf[0..bot_token_len], token_ptr[0..bot_token_len]);
}

/// Reset all per-DC state (session/auth key, stage, transport) so a fresh
/// handshake can run — used on DC migration where the auth key is re-derived.
export fn tz_reset() void {
    if (session) |*s| s.deinit(allocator);
    session = null;
    stage = .idle;
    current_dc_id = 2;
    ws_transport.reset(fillRandom, current_dc_id);
}

// Session persistence. Layout mirrors native Storage.SessionData so the same
// blob could be shared across platforms. auth_key/auth_key_id/server_salt are
// the durable state; session_id/seq_no are per-connection and re-derived.
const SessionData = extern struct {
    auth_key: [256]u8,
    auth_key_id: i64,
    server_salt: i64,
    dc_id: u8,
    is_home: bool = false,
    _pad: [6]u8 = .{0} ** 6,
};

/// Serialize the current session into `buf`. Returns bytes written, or 0 if no
/// session (yet). The host persists this (e.g. IndexedDB) keyed by dc.
export fn tz_export_session(buf: [*]u8, buf_len: usize) usize {
    const s = session orelse return 0;
    if (buf_len < @sizeOf(SessionData)) return 0;
    var data = SessionData{
        .auth_key = s.auth_key,
        .auth_key_id = s.auth_key_id,
        .server_salt = s.server_salt,
        .dc_id = @intCast(@abs(@as(i16, current_dc_id))),
    };
    @memcpy(buf[0..@sizeOf(SessionData)], std.mem.asBytes(&data));
    return @sizeOf(SessionData);
}

/// Restore a previously persisted session. On success the connection can skip
/// the DH handshake (caller must still send auth/init). Returns 1 on success,
/// 0 if the blob is invalid or absent.
export fn tz_import_session(buf: [*]const u8, buf_len: usize) i32 {
    if (buf_len < @sizeOf(SessionData)) return 0;
    const data: *const SessionData = @ptrCast(@alignCast(buf));
    if (data.auth_key_id == 0) return 0;

    if (session) |*s| s.deinit(allocator);
    session = Session.init(data.auth_key, data.auth_key_id, data.server_salt, wasm_entropy);
    stage = .ready;
    log("session restored from persistence");
    setStatus("Session restored, skipping DH handshake");
    return 1;
}

export fn tz_ws_open() void {
    ws_transport.reset(fillRandom, current_dc_id);
    if (ws_transport.getInitFrame()) |init_frame| {
        js_ws_send(init_frame.ptr, init_frame.len);
    }
    // Session restored from persistence: skip DH, go straight to auth.
    if (stage == .ready and session != null) {
        setStatus("WebSocket opened, session active — authenticating...");
        if (bot_token_len > 0) {
            authWithBotToken() catch {
                log("bot auth failed");
                setStatus("bot auth failed");
            };
        } else {
            exportLoginQr() catch {
                log("exportLoginQr failed");
                setStatus("login token export failed");
            };
        }
        return;
    }
    setStatus("WebSocket opened, starting Obfuscated2 DH key exchange...");
    startDhHandshake() catch {
        log("DH handshake start failed");
        setStatus("DH handshake failed");
    };
}

fn startDhHandshake() !void {
    ak = AuthKey.init(wasm_entropy);
    var req_buf: [128]u8 = undefined;
    const req = try ak.start(&req_buf);
    try sendPlainMsg(req);
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

        // Drive the shared Sans-I/O handshake state machine with this response.
        var out_buf: [512]u8 = undefined;
        switch (try ak.step(payload, allocator, &out_buf)) {
            .send => |next| {
                try sendPlainMsg(next);
                setStatus("DH handshake step sent...");
            },
            .done => |result| {
                stage = .ready;
                setStatus("DH Key Exchange complete! Auth Key established.");
                log("DH Key Exchange SUCCESS! Ready for MTProto 2.0 Encrypted RPCs.");

                if (session) |*s| s.deinit(allocator);
                session = Session.init(result.auth_key, result.auth_key_id, result.server_salt, wasm_entropy);
                session.?.time_offset = result.time_offset;

                js_on_session_ready();
                if (bot_token_len > 0) {
                    try authWithBotToken();
                } else {
                    setStatus("Exporting Login Token...");
                    try exportLoginQr();
                }
            },
        }
        return;
    }

    // Handle encrypted frames
    if (session) |*s| {
        const decrypted = s.decrypt(frame, allocator) catch |e| {
            // diagnostics: distinguish wrong-key from framing errors
            if (frame.len >= 8) {
                const frame_key_id = std.mem.readInt(i64, frame[0..8], .little);
                var dbg_buf: [160]u8 = undefined;
                const dbg = std.fmt.bufPrint(&dbg_buf, "Decrypt error {s}: frame_key_id={x} local={x} flen={d}", .{
                    @errorName(e), frame_key_id, s.auth_key_id, frame.len,
                }) catch "Decrypt error";
                log(dbg);
            } else {
                log("Decrypt error: short frame");
            }
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

/// Bot login: after DH, send auth.importBotAuthorization with the token.
fn authWithBotToken() !void {
    if (session == null or stage != .ready) return;
    const req = functions.auth.ImportBotAuthorization{
        .flags = 0,
        .api_id = api_id,
        .api_hash = api_hash_buf[0..api_hash_len],
        .bot_auth_token = bot_token_buf[0..bot_token_len],
    };
    const req_bytes = try codec.encodeAlloc(req, allocator);
    defer allocator.free(req_bytes);

    const wrapped = try wrapInit(allocator, api_id, req_bytes);
    defer allocator.free(wrapped);

    const enc = try session.?.encrypt(wrapped, allocator, true);
    defer allocator.free(enc.data);

    try sendEncryptedMsg(enc.data);
    setStatus("auth.importBotAuthorization sent, awaiting auth...");
    log("auth.importBotAuthorization sent");
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

            // DC migration: the account lives on another datacenter. Hand the
            // target dc_id to the host so it can reconnect there (new WebSocket
            // + fresh DH handshake; auth key is per-DC so it must be re-created).
            if (err.migrateDc()) |dc_id| {
                log("DC migration requested");
                js_on_migrate(dc_id);
            }
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

        // auth.Authorization (0x2ea2c0d4) — bot login succeeded
        if (inner_cid == 0x2ea2c0d4) {
            setStatus("Bot login successful! Authorized!");
            log("auth.importBotAuthorization succeeded!");
            js_on_login_success(1);
            return;
        }
    }

    // --- push updates (updates / updatesCombined containers) ---
    // No pts/seq ordering here (the full SyncEngine is native-side); for the
    // POC we extract each new message and hand it to the host for storage.
    if (cid == types.UpdatesCombined.cid) {
        var r: std.Io.Reader = .fixed(payload[4..]);
        const upd = try codec.decodeStructBody(types.UpdatesCombined, &r, allocator);
        try persistUpdateContainer(upd.updates);
        return;
    }
    if (cid == types.Updates.cid) {
        var r: std.Io.Reader = .fixed(payload[4..]);
        const upd = try codec.decodeStructBody(types.Updates, &r, allocator);
        try persistUpdateContainer(upd.updates);
        return;
    }
}

fn peerIdOf(peer: unions.Peer) ?i64 {
    return switch (peer) {
        .PeerUser => |p| p.user_id,
        .PeerChat => |p| p.chat_id,
        .PeerChannel => |p| p.channel_id,
    };
}

fn persistUpdateContainer(updates: []const unions.Update) !void {
    for (updates) |u| switch (u) {
        .UpdateNewMessage => |n| try persistMessage(n.message),
        .UpdateNewChannelMessage => |n| try persistMessage(n.message),
        .UpdateEditMessage => |n| try persistMessage(n.message),
        .UpdateEditChannelMessage => |n| try persistMessage(n.message),
        else => {},
    };
}

fn persistMessage(msg: unions.Message) !void {
    const m = switch (msg) {
        .Message => |m| m,
        else => return, // service/empty messages skipped for the POC
    };
    const peer_id = peerIdOf(m.peer_id) orelse return;
    const from_id: i64 = if (m.from_id.value) |f| peerIdOf(f) orelse 0 else 0;
    js_on_message(
        peer_id,
        from_id,
        m.date,
        m.id,
        m.out.value != null,
        m.message.ptr,
        m.message.len,
    );
}
