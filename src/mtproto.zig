const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const codec = @import("codec");
const types = @import("types");

// MTProto internal IDs not in schema
const cidMsgContainer: u32 = 0x73f1f8dc;
const cidRpcResult: u32 = 0xf35c6d01;
const cidGzipPacked: u32 = 0x3072cfa1;

const PendingRequest = struct {
    buf: [1][]u8,
    queue: std.Io.Queue([]u8),
    plaintext: []const u8 = &.{},

    fn init() PendingRequest {
        // SAFETY: buf is unread until queue pushes into it; queue and plaintext are set below.
        var pr: PendingRequest = undefined;
        pr.queue = std.Io.Queue([]u8).init(&pr.buf);
        pr.plaintext = &.{};
        return pr;
    }
};

const LoopResult = union(enum) {
    read: anyerror!void,
    write: anyerror!void,
    ping: anyerror!void,
};

/// Low-level MTProto transport over a single TCP connection.
/// Handler must implement: fn onUpdate(self: *Handler, io: Io, payload: []const u8) void
pub fn MtProto(comptime Handler: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        session: Session,
        transport: Transport,
        write_queue: std.Io.Queue([]const u8),
        write_queue_buf: [32][]const u8,
        pending: std.AutoHashMap(i64, *PendingRequest),
        pending_mutex: std.Io.Mutex = .init,
        // Serializes session.encrypt across readLoop (flushAcks/retryPending),
        // pingLoop (ping/fetchSalts), and caller threads (call). encrypt mutates
        // seq_no/last_msg_id and the shared encrypt_scratch buffer.
        encrypt_mutex: std.Io.Mutex = .init,
        pending_acks: std.ArrayListUnmanaged(i64) = .empty,
        salts: std.ArrayListUnmanaged(types.FutureSalt) = .empty,
        salt_valid_until: i64 = 0,
        server_time_offset: i64 = 0,
        pong_event: std.Io.Event = .unset,
        select_buf: [3]LoopResult,
        select: ?std.Io.Select(LoopResult) = null,
        handler: *Handler,

        pub fn init(
            allocator: Allocator,
            transport: Transport,
            session: Session,
            handler: *Handler,
        ) !*Self {
            const self = try allocator.create(Self);
            // SAFETY: write_queue_buf/write_queue are initialized by the Queue.init call below;
            //         select_buf is initialized by Select.init inside run() before any use.
            self.* = .{
                .allocator = allocator,
                .session = session,
                .transport = transport,
                .write_queue_buf = undefined,
                .write_queue = undefined,
                .select_buf = undefined,
                .pending = std.AutoHashMap(i64, *PendingRequest).init(allocator),
                .handler = handler,
            };
            self.write_queue = std.Io.Queue([]const u8).init(&self.write_queue_buf);
            // The DH handshake ran readFrame on the stack-allocated transport, so any
            // lazily-created reader points at a now-stale buffer. Reset it to re-init at
            // this struct's stable heap address. Safe: server is idle until our first
            // encrypted message, so no buffered bytes are lost.
            self.transport.reader = null;
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.salts.deinit(self.allocator);
            self.pending_acks.deinit(self.allocator);
            self.pending.deinit();
            self.session.deinit(self.allocator);
            self.allocator.destroy(self);
        }

        /// Start readLoop, writeLoop, pingLoop concurrently. Call join() to wait.
        pub fn run(self: *Self, io: Io) !void {
            self.select = std.Io.Select(LoopResult).init(io, &self.select_buf);
            try self.select.?.concurrent(.read, readLoop, .{ self, io });
            try self.select.?.concurrent(.write, writeLoop, .{ self, io });
            try self.select.?.concurrent(.ping, pingLoop, .{ self, io });
        }

        /// Threadsafe. Signals the connection to close.
        pub fn close(self: *Self, io: Io) void {
            self.write_queue.close(io);
            self.pong_event.set(io);
        }

        /// Block until all loops exit. Safe to call multiple times.
        pub fn join(self: *Self) void {
            const s = &(self.select orelse return);
            _ = s.await() catch |err| std.log.debug("select await: {}", .{err});
            s.cancelDiscard();
            self.select = null;
        }

        /// Encrypt under encrypt_mutex. Required for every outbound message since
        /// readLoop, pingLoop, and caller threads all encrypt concurrently.
        fn encryptLocked(self: *Self, plaintext: []const u8, io: Io, content_related: bool) !Session.EncryptResult {
            self.encrypt_mutex.lockUncancelable(io);
            defer self.encrypt_mutex.unlock(io);
            return self.session.encrypt(plaintext, self.allocator, io, content_related);
        }

        /// Send a serialized TL request, return the raw response bytes (caller frees).
        pub fn call(self: *Self, io: Io, request: []const u8) ![]u8 {
            var pr = PendingRequest.init();
            pr.plaintext = try gzipWrap(request, self.allocator);
            errdefer self.allocator.free(pr.plaintext);

            const enc = try self.encryptLocked(pr.plaintext, io, true);
            var enc_sent = false;
            defer if (!enc_sent) self.allocator.free(enc.data);

            {
                self.pending_mutex.lockUncancelable(io);
                defer self.pending_mutex.unlock(io);
                try self.pending.put(enc.msg_id, &pr);
            }

            self.write_queue.putOne(io, enc.data) catch |err| {
                self.pending_mutex.lockUncancelable(io);
                _ = self.pending.remove(enc.msg_id);
                self.pending_mutex.unlock(io);
                return err;
            };
            enc_sent = true;

            const result = pr.queue.getOne(io) catch |err| {
                self.pending_mutex.lockUncancelable(io);
                _ = self.pending.remove(enc.msg_id);
                self.pending_mutex.unlock(io);
                return err;
            };
            self.allocator.free(pr.plaintext);
            return result;
        }

        fn readLoop(self: *Self, io: Io) !void {
            defer self.drainPending(io);
            while (true) {
                const frame = self.transport.readFrame(io, self.allocator) catch |err| {
                    std.log.debug("readLoop: readFrame failed: {}", .{err});
                    break;
                };
                defer self.allocator.free(frame);
                if (frame.len == 4) {
                    const code = std.mem.readInt(i32, frame[0..4], .little);
                    if (code == -404) {
                        std.log.warn("readLoop: auth key not found (-404), terminating connection", .{});
                        break;
                    }
                    std.log.warn("readLoop: server transport error: {}", .{code});
                    continue;
                }
                // payload borrows session.decrypt_scratch; valid only until the next
                // decrypt. dispatch consumes it synchronously (async paths copy it).
                const decrypted = self.session.decrypt(frame, self.allocator) catch |e| {
                    std.log.debug("readLoop: decrypt failed: {} (frame_len={})", .{ e, frame.len });
                    continue;
                };
                self.dispatch(io, decrypted.payload, decrypted.msg_id) catch |err| std.log.debug("dispatch: {}", .{err});
                self.flushAcks(io);
            }
        }

        fn dispatch(self: *Self, io: Io, payload: []const u8, msg_id: i64) anyerror!void {
            if (payload.len < 4) return;
            const cid = std.mem.readInt(u32, payload[0..4], .little);
            std.log.debug("recv cid=0x{x:0>8}", .{cid});
            switch (cid) {
                cidMsgContainer => try self.dispatchContainer(io, payload),
                cidRpcResult => {
                    self.queueAck(msg_id);
                    try self.deliverRpcResult(io, payload);
                },
                cidGzipPacked => {
                    self.queueAck(msg_id);
                    try self.handleGzip(io, payload);
                },
                types.MsgsAck.cid => {},
                types.FutureSalts.cid => self.parseFutureSalts(payload, io),
                types.NewSessionCreated.cid => {
                    var r: std.Io.Reader = .fixed(payload);
                    const m = codec.decode(types.NewSessionCreated, &r, self.allocator) catch |e| {
                        std.log.warn("new_session_created: decode failed: {}", .{e});
                        return;
                    };
                    self.session.server_salt = m.server_salt;
                },
                types.BadServerSalt.cid => {
                    var r: std.Io.Reader = .fixed(payload);
                    const m = codec.decode(types.BadServerSalt, &r, self.allocator) catch {
                        std.log.warn("bad_server_salt: decode failed, draining", .{});
                        return self.drainPending(io);
                    };
                    self.session.server_salt = m.new_server_salt;
                    std.log.debug("bad_server_salt, updated salt, retrying {} pending", .{self.pending.count()});
                    self.pong_event.set(io);
                    self.retryPending(io);
                },
                types.BadMsgNotification.cid => {
                    var r: std.Io.Reader = .fixed(payload);
                    const m = codec.decode(types.BadMsgNotification, &r, self.allocator) catch {
                        std.log.warn("bad_msg_notification: decode failed, draining", .{});
                        return self.drainPending(io);
                    };
                    std.log.warn("bad_msg_notification error_code={}", .{m.error_code});
                    switch (m.error_code) {
                        // Msg ID too low/high: correct clock offset from server msg_id.
                        16, 17 => {
                            self.session.correctTimeOffset(msg_id, io);
                            self.retryPending(io);
                        },
                        // Other seqno/msg_id issues: retry with corrected values.
                        18, 19, 20, 32, 33, 48 => self.retryPending(io),
                        else => self.drainPending(io),
                    }
                },
                types.Pong.cid => {
                    self.pong_event.set(io);
                },
                else => {
                    self.queueAck(msg_id);
                    self.handler.onUpdate(io, payload);
                },
            }
        }

        /// Enqueue msg_id to be acked on the next flushAcks. msg_id == 0 marks a
        /// message dispatched from inside a gzip container, whose outer id is
        /// already queued. OOM only skips the ack; the server will retry delivery.
        fn queueAck(self: *Self, msg_id: i64) void {
            if (msg_id == 0) return;
            self.pending_acks.append(self.allocator, msg_id) catch |err| std.log.debug("ack enqueue: {}", .{err});
        }

        fn handleGzip(self: *Self, io: Io, payload: []const u8) !void {
            var r: std.Io.Reader = .fixed(payload[4..]);
            const compressed = try codec.deserialize.bytes(&r, self.allocator);
            defer self.allocator.free(compressed);
            var in = std.Io.Reader.fixed(compressed);
            var aw: std.Io.Writer.Allocating = .init(self.allocator);
            defer aw.deinit();
            var decomp: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
            _ = try decomp.reader.streamRemaining(&aw.writer);
            // Outer msg already acked by caller; pass 0 so inner doesn't double-ack.
            try self.dispatch(io, aw.written(), 0);
        }

        fn dispatchContainer(self: *Self, io: Io, payload: []const u8) !void {
            if (payload.len < 8) return;
            const count = std.mem.readInt(u32, payload[4..8], .little);
            var pos: usize = 8;
            for (0..count) |_| {
                if (pos + 16 > payload.len) break;
                const inner_msg_id = std.mem.readInt(i64, payload[pos..][0..8], .little);
                const bytes = std.mem.readInt(u32, payload[pos + 12 ..][0..4], .little);
                const body_end = pos + 16 + bytes;
                if (body_end > payload.len) break;
                self.dispatch(io, payload[pos + 16 .. body_end], inner_msg_id) catch |err| std.log.debug("dispatch: {}", .{err});
                pos = body_end;
            }
        }

        fn flushAcks(self: *Self, io: Io) void {
            if (self.pending_acks.items.len == 0) return;
            // 4 (cid) + 4 (vector cid) + 4 (count) + 8*N (ids)
            const max_ids = 64;
            var buf: [4 + 4 + 4 + 8 * max_ids]u8 = undefined;
            const ids = self.pending_acks.items[0..@min(self.pending_acks.items.len, max_ids)];
            var w: std.Io.Writer = .fixed(&buf);
            // buf is sized for exactly max_ids; these writes cannot overflow it.
            w.writeInt(u32, types.MsgsAck.cid, .little) catch @panic("ack buf too small");
            w.writeInt(u32, 0x1cb5c415, .little) catch @panic("ack buf too small"); // vector cid
            w.writeInt(u32, @intCast(ids.len), .little) catch @panic("ack buf too small");
            for (ids) |id| w.writeInt(i64, id, .little) catch @panic("ack buf too small");
            self.pending_acks.clearRetainingCapacity();
            const enc = self.encryptLocked(w.buffered(), io, false) catch |e| {
                std.log.debug("flush_acks encrypt: {}", .{e});
                return;
            };
            self.write_queue.putOne(io, enc.data) catch self.allocator.free(enc.data);
        }

        fn deliverRpcResult(self: *Self, io: Io, payload: []const u8) !void {
            if (payload.len < 12) return;
            const req_msg_id = std.mem.readInt(i64, payload[4..12], .little);
            const pr = blk: {
                self.pending_mutex.lockUncancelable(io);
                defer self.pending_mutex.unlock(io);
                const e = self.pending.fetchRemove(req_msg_id) orelse {
                    std.log.debug("deliverRpcResult: no pending for msg_id={x}", .{req_msg_id});
                    return;
                };
                break :blk e.value;
            };
            const result = try self.allocator.dupe(u8, payload[12..]);
            errdefer self.allocator.free(result);
            try pr.queue.putOne(io, result);
        }

        fn retryPending(self: *Self, io: Io) void {
            var snap: std.ArrayListUnmanaged(*PendingRequest) = .empty;
            {
                self.pending_mutex.lockUncancelable(io);
                var it = self.pending.valueIterator();
                while (it.next()) |pr| snap.append(self.allocator, pr.*) catch |err|
                    std.log.warn("retryPending: drop pending request: {}", .{err});
                self.pending.clearRetainingCapacity();
                self.pending_mutex.unlock(io);
            }
            defer snap.deinit(self.allocator);

            for (snap.items) |pr| {
                const enc = self.encryptLocked(pr.plaintext, io, true) catch {
                    pr.queue.close(io);
                    continue;
                };
                {
                    self.pending_mutex.lockUncancelable(io);
                    self.pending.put(enc.msg_id, pr) catch {
                        self.pending_mutex.unlock(io);
                        self.allocator.free(enc.data);
                        pr.queue.close(io);
                        continue;
                    };
                    self.pending_mutex.unlock(io);
                }
                self.write_queue.putOne(io, enc.data) catch {
                    self.pending_mutex.lockUncancelable(io);
                    _ = self.pending.remove(enc.msg_id);
                    self.pending_mutex.unlock(io);
                    self.allocator.free(enc.data);
                    pr.queue.close(io);
                };
            }
        }

        fn drainPending(self: *Self, io: Io) void {
            var snap: std.ArrayListUnmanaged(*PendingRequest) = .empty;
            defer snap.deinit(self.allocator);
            self.pending_mutex.lockUncancelable(io);
            var it = self.pending.valueIterator();
            while (it.next()) |pr| snap.append(self.allocator, pr.*) catch |err|
                std.log.debug("drainPending: drop pending request: {}", .{err});
            self.pending.clearRetainingCapacity();
            self.pending_mutex.unlock(io);
            for (snap.items) |pr| pr.queue.close(io);
        }

        fn writeLoop(self: *Self, io: Io) !void {
            while (true) {
                const data = self.write_queue.getOne(io) catch break;
                defer self.allocator.free(data);
                self.transport.writeFrame(io, data) catch break;
            }
        }

        fn pingLoop(self: *Self, io: Io) anyerror!void {
            const funcs = @import("functions");
            while (true) {
                std.Io.sleep(io, std.Io.Duration.fromSeconds(60), .awake) catch break;
                self.checkSaltRefresh(io);

                var ping_id_bytes: [8]u8 = undefined;
                io.random(&ping_id_bytes);
                const ping_id = std.mem.readInt(i64, &ping_id_bytes, .little);

                var ping_buf: [32]u8 = undefined;
                var pw: std.Io.Writer = .fixed(&ping_buf);
                codec.encode(funcs.PingDelayDisconnect{ .ping_id = ping_id, .disconnect_delay = 75 }, &pw) catch break;
                const bytes = pw.buffered();
                self.pong_event.reset();
                const enc = self.encryptLocked(bytes, io, false) catch break;
                self.write_queue.putOne(io, enc.data) catch {
                    self.allocator.free(enc.data);
                    break;
                };
                self.pong_event.waitTimeout(io, .{ .duration = .{
                    .raw = std.Io.Duration.fromSeconds(15),
                    .clock = .awake,
                } }) catch {
                    std.log.warn("ping timeout", .{});
                    break;
                };
            }
        }

        fn fetchSalts(self: *Self, io: Io) void {
            const funcs = @import("functions");
            var req_buf: [8]u8 = undefined;
            var w: std.Io.Writer = .fixed(&req_buf);
            // req_buf is exactly cid + i32; this encode cannot overflow it.
            codec.encode(funcs.GetFutureSalts{ .num = 64 }, &w) catch @panic("salts req buf too small");
            // Service message: fire-and-forget. Server responds with FutureSalts
            // as a standalone message (not rpc_result), handled by parseFutureSalts in dispatch.
            const enc = self.encryptLocked(w.buffered(), io, false) catch |e| {
                std.log.debug("fetch_salts encrypt: {}", .{e});
                return;
            };
            self.write_queue.putOne(io, enc.data) catch self.allocator.free(enc.data);
        }

        fn parseFutureSalts(self: *Self, raw: []const u8, io: Io) void {
            var r: std.Io.Reader = .fixed(raw);
            const fs = codec.decode(types.FutureSalts, &r, self.allocator) catch |e| {
                std.log.debug("future_salts decode: {}", .{e});
                return;
            };
            defer codec.free(types.FutureSalts, fs, self.allocator);
            const local_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
            self.server_time_offset = @as(i64, fs.now) - @as(i64, @intCast(@divTrunc(local_ns, std.time.ns_per_s)));
            self.salts.clearRetainingCapacity();
            for (fs.salts.items) |s| self.salts.append(self.allocator, s) catch break;
            self.applySalt(fs.now);
        }

        fn serverNow(self: *Self, io: Io) i64 {
            const local_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
            return @as(i64, @intCast(@divTrunc(local_ns, std.time.ns_per_s))) + self.server_time_offset;
        }

        fn applySalt(self: *Self, server_now: i32) void {
            for (self.salts.items) |s| {
                if (s.valid_since <= server_now and server_now < s.valid_until) {
                    if (s.salt != self.session.server_salt) {
                        std.log.debug("salt switched (valid until {})", .{s.valid_until});
                        self.session.server_salt = s.salt;
                        self.salt_valid_until = @as(i64, s.valid_until);
                    }
                    return;
                }
            }
        }

        fn checkSaltRefresh(self: *Self, io: Io) void {
            const now = self.serverNow(io);
            // Switch salt if within 5 minutes of expiry
            if (now + 300 < self.salt_valid_until) return;
            self.applySalt(@intCast(now & 0x7fffffff));
            // Refetch if few future salts remain
            var ahead: usize = 0;
            for (self.salts.items) |s| {
                if (@as(i64, s.valid_since) > now) ahead += 1;
            }
            if (ahead < 4) self.fetchSalts(io);
        }
    };
}

const gzipThreshold = 512;

pub const Session = @import("mtproto/Session.zig");
pub const auth_key = @import("mtproto/auth_key.zig");

fn gzipWrap(data: []const u8, allocator: Allocator) ![]u8 {
    if (data.len <= gzipThreshold) return allocator.dupe(u8, data);

    const window = try allocator.alloc(u8, std.compress.flate.max_window_len);
    defer allocator.free(window);

    var out = try std.Io.Writer.Allocating.initCapacity(allocator, 16);
    defer out.deinit();

    var comp = try std.compress.flate.Compress.init(&out.writer, window, .gzip, .level_4);
    var in: std.Io.Reader = .fixed(data);
    _ = try in.streamRemaining(&comp.writer);
    try comp.finish();

    const compressed = out.written();
    if (compressed.len >= data.len) return allocator.dupe(u8, data);

    var w = try std.Io.Writer.Allocating.initCapacity(allocator, 4 + compressed.len + 16);
    defer w.deinit();
    try w.writer.writeInt(u32, cidGzipPacked, .little);
    try codec.serialize.bytes(&w.writer, compressed);
    return try w.toOwnedSlice();
}
