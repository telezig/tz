const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Connector = @import("Connector.zig");
const Storage = @import("Storage.zig");
const codec = @import("codec");
const types = @import("types");
const unions = @import("unions");
const functions = @import("functions");
const RpcError = @import("RpcError.zig");
const ulog = std.log.scoped(.updates);

pub const Context = @import("Context.zig");
pub const Entities = Context.Entities;
pub const Response = Context.Response;
const decodeOwned = Context.decodeOwned;

pub const Handler = struct {
    cid: u32,
    dispatch: *const fn (ctx: Context, update: unions.Update) anyerror!void,
};

pub fn handler(
    comptime UpdateType: type,
    comptime cb: fn (Context, UpdateType) anyerror!void,
) Handler {
    return .{
        .cid = UpdateType.cid,
        .dispatch = struct {
            fn dispatch(ctx: Context, update: unions.Update) anyerror!void {
                switch (update) {
                    inline else => |inner| if (@TypeOf(inner) == UpdateType)
                        try cb(ctx, inner),
                }
            }
        }.dispatch,
    };
}

var subConnDummy: u8 = 0;
const sub_conn_noop_handler = Connector.UpdateHandler{
    .ptr = &subConnDummy,
    .vtable = &.{ .handle = struct {
        fn h(_: *anyopaque, _: Io, _: []const u8) void {}
    }.h },
};

/// True if `raw` is a serialized `rpc_error` rather than a normal response body.
fn isRpcError(raw: []const u8) bool {
    return raw.len >= 4 and std.mem.readInt(u32, raw[0..4], .little) == types.RpcError.cid;
}

pub const ClientOptions = struct {
    dc: Connector.DC = Connector.default_dcs[1],
    bot_token: ?[]const u8 = null,
    /// Called once after the first successful connection, before the update loop.
    /// Receives an opaque pointer to the Client; cast with @ptrCast(@alignCast(ptr)).
    /// Use this for interactive user auth (sendCode / signIn). Ignored when bot_token is set.
    /// Receives a `Context` — call TL functions through `ctx.call` / `ctx.exec`, same as
    /// in update handlers; `ctx.api_id` / `ctx.api_hash` are available for the initial sendCode.
    auth_fn: ?*const fn (Context) anyerror!void = null,
    api_id: i32,
    api_hash: []const u8,
    storage: Storage,
    /// Maximum attempts for a single RPC before a transient error (FLOOD_WAIT,
    /// 500 internal, -503 timeout) is given up on and surfaced. Each retry may sleep
    /// — FLOOD_WAIT waits the server-requested seconds — so this bounds the attempt
    /// count, not wall-clock time.
    max_rpc_retries: u32 = 5,
    /// Called once after the connection is authenticated, before the update loop
    /// starts — for both bots and user sessions. Use for one-time setup such as
    /// registering the command menu (`bots.SetBotCommands`). Receives a `Context`,
    /// same as update handlers. Not re-run across reconnects/DC migrations.
    on_ready: ?*const fn (Context) anyerror!void = null,
    /// Number of parallel part requests for file download/upload. Each worker
    /// issues `upload.GetFile`/`SaveFilePart` concurrently, multiplexed over the
    /// same connection (responses matched by msg_id). 1 disables parallelism.
    file_workers: usize = 4,
};

const CdnConn = struct {
    conn: *Connector,
    mem: *Storage.Memory, // heap-allocated; CDN connections don't persist auth
};

/// Client(handlers) — handlers is a comptime-known slice of Handler.
pub fn Client(comptime handlers: []const Handler) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        opts: ClientOptions,
        primary: ?*Connector = null,
        closed: bool = false,
        dc_resolved: bool = false,
        bot_id: ?i64 = null,
        user_authorized: bool = false,
        ready_called: bool = false,
        dc_list: ?[]Connector.DC = null,
        sub_conns: std.AutoHashMapUnmanaged(u8, *Connector) = .empty,
        sub_conns_mu: std.Io.Mutex = std.Io.Mutex.init,
        cdn_dcs: std.AutoHashMapUnmanaged(i32, std.Io.net.IpAddress) = .empty,
        cdn_conns: std.AutoHashMapUnmanaged(i32, CdnConn) = .empty,
        cdn_conns_mu: std.Io.Mutex = .init,
        state: @import("State.zig") = .{},
        mb_mutex: std.Io.Mutex = .init,
        state_initialized: bool = false,
        sync_event: std.Io.Event = .unset,
        sync_stop: bool = false,

        pub fn init(allocator: Allocator, opts: ClientOptions) !*Self {
            const c = try allocator.create(Self);
            c.* = .{ .allocator = allocator, .opts = opts };
            return c;
        }

        pub fn deinit(self: *Self) void {
            if (self.dc_list) |list| self.allocator.free(list);
            var it = self.sub_conns.valueIterator();
            while (it.next()) |conn| conn.*.deinit();
            self.sub_conns.deinit(self.allocator);
            var cdn_it = self.cdn_conns.valueIterator();
            while (cdn_it.next()) |entry| {
                entry.conn.deinit();
                entry.mem.deinit(self.allocator);
                self.allocator.destroy(entry.mem);
            }
            self.cdn_conns.deinit(self.allocator);
            self.cdn_dcs.deinit(self.allocator);
            self.state.deinit(self.allocator);
            self.allocator.destroy(self);
        }

        /// Blocks until close() is called. Reconnects automatically on disconnect.
        pub fn run(self: *Self, io: Io) !void {
            try initRandomCounter(io);
            var backoff_ms: u64 = 100;
            while (!self.closed) {
                self.runOnce(io) catch |err| {
                    if (self.closed) return;
                    if (err == error.SessionInvalid) {
                        std.log.warn("session invalid, clearing stored session", .{});
                        const dc_id = if (self.primary) |p| p.dc_id else 0;
                        var blank = std.mem.zeroes(Storage.SessionData);
                        blank.dc_id = dc_id;
                        self.opts.storage.save(io, self.allocator, blank) catch |e|
                            std.log.warn("failed to clear session: {}", .{e});
                        self.user_authorized = false;
                    }
                    // Jitter: ±20% of current backoff to avoid thundering herd.
                    var jitter_byte: [1]u8 = undefined;
                    io.random(&jitter_byte);
                    const jitter = backoff_ms * (80 + @as(u64, jitter_byte[0] % 41)) / 100;
                    std.log.warn("disconnected: {}, reconnecting in {}ms", .{ err, jitter });
                    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(jitter)), .awake) catch |e| std.log.debug("sleep: {}", .{e});
                    backoff_ms = @min(backoff_ms * 2, 30_000);
                    continue;
                };
                backoff_ms = 100;
            }
        }

        pub fn close(self: *Self, io: Io) void {
            self.closed = true;
            if (self.primary) |c| c.close(io);
        }

        /// Send a typed TL request, return the decoded response. The caller owns the
        /// result and must free it with `resp.deinit()`; use `exec` to discard it.
        /// Used on the internal sync/auth path: RPC errors surface as Zig errors
        /// (`error.DcMigrate`, `error.SessionInvalid`, …) for the run loop to act on.
        pub fn call(self: *Self, io: Io, request: anytype) !Response(@TypeOf(request).Response) {
            const bytes = try codec.encodeAlloc(request, self.allocator);
            defer self.allocator.free(bytes);
            const raw = try callImpl(self, io, bytes);
            defer self.allocator.free(raw);
            return decodeOwned(@TypeOf(request).Response, raw, self.allocator);
        }

        /// Send a typed TL request, discard the response.
        pub fn exec(self: *Self, io: Io, request: anytype) !void {
            const bytes = try codec.encodeAlloc(request, self.allocator);
            defer self.allocator.free(bytes);
            self.allocator.free(try callImpl(self, io, bytes));
        }

        /// Build the `Context` handed to auth_fn, on_ready, and update handlers.
        /// `entities` carries the users/chats from the current update batch (empty
        /// for the setup hooks).
        fn makeContext(self: *Self, io: Io, entities: Entities) Context {
            return .{
                .client = self,
                .io = io,
                .allocator = self.allocator,
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
                .entities = entities,
                .peer_cache = &self.state.peers,
                .mb_mutex = &self.mb_mutex,
                .callFn = callImpl,
                .callFileFn = callFileImpl,
                .callCdnFn = callCdnImpl,
                .loginQrFn = loginQrImpl,
                .file_workers = self.opts.file_workers,
            };
        }

        /// Retry engine behind `Context.call`/`exec` (handler/auth path). Returns the
        /// owned response body, or maps the `rpc_error` to a Zig error via
        /// `handleRpcError` (which also auto-retries FLOOD_WAIT and transient faults).
        fn callImpl(ptr: *anyopaque, io2: Io, bytes: []const u8) anyerror![]u8 {
            const self: *Self = @ptrCast(@alignCast(ptr));
            var attempt: u32 = 0;
            while (true) : (attempt += 1) {
                const raw = try self.callRaw(io2, bytes);
                if (!isRpcError(raw)) return raw;
                const r = self.handleRpcError(io2, raw, attempt + 1 < self.opts.max_rpc_retries);
                self.allocator.free(raw);
                try r; // void => retryable (already slept); error => surface
            }
        }

        /// Like `callImpl` but for file RPCs: FILE_MIGRATE routes to a sub-connection
        /// on the file DC instead of tearing down the primary.
        fn callFileImpl(ptr: *anyopaque, io2: Io, bytes: []const u8) anyerror![]u8 {
            const self: *Self = @ptrCast(@alignCast(ptr));
            var attempt: u32 = 0;
            while (true) : (attempt += 1) {
                const raw = try self.callRaw(io2, bytes);
                if (!isRpcError(raw)) return raw;
                if (RpcError.parse(raw).migrateDc()) |dc_id| {
                    std.log.debug("file: FILE_MIGRATE to DC {}", .{dc_id});
                    self.allocator.free(raw);
                    return self.callRawOnDc(io2, dc_id, bytes);
                }
                const r = self.handleRpcError(io2, raw, attempt + 1 < self.opts.max_rpc_retries);
                self.allocator.free(raw);
                try r;
            }
        }

        fn callCdnImpl(ptr: *anyopaque, io2: Io, dc_id: i32, bytes: []const u8) anyerror![]u8 {
            const self: *Self = @ptrCast(@alignCast(ptr));
            const conn = try self.getOrCreateCdnConn(io2, dc_id);
            return self.callViaConnector(io2, conn, bytes);
        }

        fn getOrCreateCdnConn(self: *Self, io2: Io, dc_id: i32) !*Connector {
            {
                try self.cdn_conns_mu.lock(io2);
                defer self.cdn_conns_mu.unlock(io2);
                if (self.cdn_conns.get(dc_id)) |entry| return entry.conn;
            }

            const addr = blk: {
                if (self.cdn_dcs.get(dc_id)) |a| break :blk a;
                try self.fetchDcList(io2);
                break :blk self.cdn_dcs.get(dc_id) orelse return error.CdnDcNotFound;
            };

            const mem = try self.allocator.create(Storage.Memory);
            errdefer self.allocator.destroy(mem);
            mem.* = .{};

            const conn = try Connector.connect(io2, self.allocator, .{
                .dc = .{ .id = 0, .addr = addr, .test_server = self.opts.dc.test_server },
                .transport = .abridged,
                .storage = mem.storage(),
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
            });
            errdefer conn.deinit();
            try conn.run(io2, sub_conn_noop_handler);
            errdefer {
                conn.close(io2);
                conn.join(io2);
            }

            try self.cdn_conns_mu.lock(io2);
            const gop = self.cdn_conns.getOrPut(self.allocator, dc_id) catch |err| {
                self.cdn_conns_mu.unlock(io2);
                return err;
            };
            if (gop.found_existing) {
                self.cdn_conns_mu.unlock(io2);
                conn.close(io2);
                conn.join(io2);
                conn.deinit();
                mem.deinit(self.allocator);
                self.allocator.destroy(mem);
                return gop.value_ptr.conn;
            }
            gop.value_ptr.* = .{ .conn = conn, .mem = mem };
            self.cdn_conns_mu.unlock(io2);
            return conn;
        }

        fn callViaConnector(self: *Self, io2: Io, c: *Connector, bytes: []const u8) ![]u8 {
            if (!c.isInitialized()) {
                c.setInitialized();
                const wrapped = try wrapInit(self.allocator, self.opts.api_id, bytes);
                defer self.allocator.free(wrapped);
                return c.call(io2, wrapped);
            }
            return c.call(io2, bytes);
        }

        fn getOrCreateSubConn(self: *Self, io2: Io, dc_id: u8) !*Connector {
            // Fast path: already exists.
            {
                try self.sub_conns_mu.lock(io2);
                defer self.sub_conns_mu.unlock(io2);
                if (self.sub_conns.get(dc_id)) |conn| return conn;
            }

            // Slow path: create outside the lock so blocking ops don't stall other coroutines.
            const dc = self.findDc(dc_id) orelse return error.DcNotFound;
            const conn = try Connector.connect(io2, self.allocator, .{
                .dc = dc,
                .transport = .abridged,
                .storage = self.opts.storage,
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
            });
            errdefer conn.deinit();
            // run() before transferAuth: loops must be running so mtp.call can complete.
            try conn.run(io2, sub_conn_noop_handler);
            errdefer {
                conn.close(io2);
                conn.join(io2);
            }
            try self.transferAuth(io2, conn, dc_id);

            // Insert under lock. Handle the race where another coroutine beat us here.
            try self.sub_conns_mu.lock(io2);
            const gop = self.sub_conns.getOrPut(self.allocator, dc_id) catch |err| {
                self.sub_conns_mu.unlock(io2);
                return err;
            };
            if (gop.found_existing) {
                // Another coroutine won the race; discard ours.
                const existing = gop.value_ptr.*;
                self.sub_conns_mu.unlock(io2);
                conn.close(io2);
                conn.join(io2);
                conn.deinit();
                return existing;
            }
            gop.value_ptr.* = conn;
            self.sub_conns_mu.unlock(io2);
            return conn;
        }

        fn removeSubConn(self: *Self, io2: Io, dc_id: u8) void {
            self.sub_conns_mu.lock(io2) catch return;
            const kv = self.sub_conns.fetchRemove(dc_id) orelse {
                self.sub_conns_mu.unlock(io2);
                return;
            };
            self.sub_conns_mu.unlock(io2);
            // Join before deinit to avoid use-after-free in the running loops.
            kv.value.close(io2);
            kv.value.join(io2);
            kv.value.deinit();
        }

        fn callRawOnDc(self: *Self, io2: Io, dc_id: u8, bytes: []const u8) ![]u8 {
            const conn = try self.getOrCreateSubConn(io2, dc_id);
            return self.callViaConnector(io2, conn, bytes) catch |err| {
                self.removeSubConn(io2, dc_id);
                return err;
            };
        }

        fn transferAuth(self: *Self, io2: Io, sub: *Connector, dc_id: u8) !void {
            const exported_resp = try self.call(io2, functions.auth.ExportAuthorization{
                .dc_id = @intCast(dc_id),
            });
            defer exported_resp.deinit();
            const exported = exported_resp.value;
            var buf: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            try codec.encode(functions.auth.ImportAuthorization{
                .id = exported.id,
                .bytes = exported.bytes,
            }, &w);
            const raw = try self.callViaConnector(io2, sub, w.buffered());
            defer self.allocator.free(raw);
            if (isRpcError(raw)) return error.AuthTransferFailed;
        }

        fn markHomeDc(self: *Self, io: Io) void {
            if (self.primary) |c| {
                c.is_home = true;
                c.saveSession(io);
            }
        }

        fn runOnce(self: *Self, io: Io) !void {
            if (!self.dc_resolved) {
                scan: for (1..Storage.max_dc_id + 1) |id| {
                    const slot = try self.opts.storage.load(io, self.allocator, @intCast(id)) orelse continue;
                    if (slot.is_home) {
                        if (Connector.findDc(slot.dc_id, self.opts.dc.test_server)) |dc| self.opts.dc = dc;
                        break :scan;
                    }
                }
                self.dc_resolved = true;
            }
            std.log.info("connecting to DC {}", .{self.opts.dc.id});
            const c = try Connector.connect(io, self.allocator, .{
                .dc = self.opts.dc,
                .transport = .abridged,
                .storage = self.opts.storage,
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
            });
            std.log.info("connected, auth key ready", .{});
            defer {
                c.close(io);
                c.join(io);
                c.saveSession(io);
                c.deinit();
                self.primary = null;
                var sub_it = self.sub_conns.valueIterator();
                while (sub_it.next()) |sub| {
                    sub.*.close(io);
                    sub.*.join(io);
                    sub.*.deinit();
                }
                self.sub_conns.clearRetainingCapacity();
            }
            self.primary = c;
            // is_home is only set after a successful auth and is persisted, so a loaded
            // home-DC session means we're already authorized — skip auth_fn re-runs.
            if (c.is_home) self.user_authorized = true;

            const update_handler: Connector.UpdateHandler = .{
                .ptr = self,
                .vtable = &.{ .handle = handleUpdate },
            };
            try c.run(io, update_handler);

            if (self.opts.bot_token) |token| {
                if (self.bot_id == null) {
                    std.log.info("authenticating bot", .{});
                    self.authBot(io, token) catch |err| switch (err) {
                        error.DcMigrate => {
                            std.log.info("migrating to DC {}", .{self.opts.dc.id});
                            return err;
                        },
                        else => return err,
                    };
                    std.log.info("bot authenticated", .{});
                    self.markHomeDc(io);
                }
            } else if (self.opts.auth_fn) |f| {
                if (!self.user_authorized) {
                    try f(self.makeContext(io, .{}));
                    self.user_authorized = true;
                    self.markHomeDc(io);
                }
            }

            // One-time post-auth setup, before the update loop. Runs for both bots
            // and user sessions; guarded so reconnects/migrations don't re-run it.
            if (!self.ready_called) {
                if (self.opts.on_ready) |f| try f(self.makeContext(io, .{}));
                self.ready_called = true;
            }

            self.initUpdateState(io) catch |err|
                std.log.warn("failed to init update state: {}", .{err});
            self.fetchDcList(io) catch |err|
                std.log.warn("failed to fetch DC list: {}", .{err});

            self.sync_stop = false;
            self.sync_event.reset();
            var sync_future = std.Io.async(io, syncLoop, .{ self, io });
            {
                self.mb_mutex.lockUncancelable(io);
                const pending = self.state.getting_diff or self.state.getting_channel_diff.count() > 0;
                self.mb_mutex.unlock(io);
                if (pending) self.sync_event.set(io);
            }
            defer {
                self.sync_stop = true;
                self.sync_event.set(io);
                _ = sync_future.await(io);
            }

            std.log.info("waiting for updates", .{});
            c.join(io);
        }

        fn fetchDcList(self: *Self, io: Io) !void {
            const config_resp = try self.call(io, functions.help.GetConfig{});
            defer config_resp.deinit();
            const config = config_resp.value;
            var list: std.ArrayList(Connector.DC) = .empty;
            defer list.deinit(self.allocator);
            for (config.dc_options) |opt| {
                if (opt.ipv6.value != null) continue;
                const addr = std.Io.net.IpAddress.parseIp4(opt.ip_address, @intCast(opt.port)) catch continue;
                if (opt.cdn.value != null) {
                    self.cdn_dcs.put(self.allocator, opt.id, addr) catch |e| std.log.debug("cdn_dcs.put: {}", .{e});
                    continue;
                }
                if (opt.media_only.value != null) continue;
                const id = std.math.cast(u8, opt.id) orelse continue;
                try list.append(self.allocator, .{ .id = id, .addr = addr, .test_server = self.opts.dc.test_server });
            }
            if (self.dc_list) |old| self.allocator.free(old);
            self.dc_list = try list.toOwnedSlice(self.allocator);
            std.log.info("DC list updated: {} entries", .{self.dc_list.?.len});
        }

        fn initUpdateState(self: *Self, io: Io) !void {
            if (self.state_initialized) return;
            if (try self.opts.storage.loadUpdateState(io, self.allocator)) |blob| {
                defer self.allocator.free(blob);
                var r: std.Io.Reader = .fixed(blob);
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                self.state.deserialize(self.allocator, &r) catch |e| {
                    std.log.warn("update state deserialize failed ({}), resetting", .{e});
                    self.state.deinit(self.allocator);
                    self.state = .{};
                };
                ulog.info("loaded state pts={} qts={} date={} seq={} channels={}", .{
                    self.state.pts,              self.state.qts,
                    self.state.date,             self.state.seq,
                    self.state.channels.count(),
                });
                if (self.state.pts != 0) self.state.getting_diff = true;
                var it = self.state.channels.keyIterator();
                while (it.next()) |k| {
                    try self.state.getting_channel_diff.put(self.allocator, k.*, {});
                }
            } else {
                ulog.info("no persisted state", .{});
            }
            const need_state = blk: {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                break :blk self.state.pts == 0;
            };
            if (need_state) {
                const st_resp = try self.call(io, functions.updates.GetState{});
                defer st_resp.deinit();
                const st = st_resp.value;
                self.mb_mutex.lockUncancelable(io);
                self.state.setState(st);
                self.mb_mutex.unlock(io);
                ulog.info("GetState -> pts={} qts={} date={} seq={}", .{ st.pts, st.qts, st.date, st.seq });
            }
            self.state_initialized = true;
        }

        fn syncLoop(self: *Self, io: Io) void {
            while (true) {
                self.sync_event.waitTimeout(io, .{ .duration = .{
                    .raw = std.Io.Duration.fromSeconds(60),
                    .clock = .awake,
                } }) catch |err| ulog.debug("syncLoop waitTimeout: {}", .{err});
                self.sync_event.reset();
                if (self.closed or self.sync_stop) return;
                ulog.debug("syncLoop wake: getting_diff={} channel_gaps={}", .{
                    self.state.getting_diff, self.state.getting_channel_diff.count(),
                });
                self.drainDifferences(io) catch |err|
                    ulog.warn("drainDifferences: {}", .{err});
            }
        }

        fn drainDifferences(self: *Self, io: Io) !void {
            var changed = false;
            var guard: usize = 0;
            while (guard < 100) : (guard += 1) {
                if (self.sync_stop) break;
                const req = blk: {
                    self.mb_mutex.lockUncancelable(io);
                    defer self.mb_mutex.unlock(io);
                    break :blk self.state.takeDifferenceRequest();
                } orelse break;
                changed = true;
                switch (req) {
                    .common => |gd| try self.fetchCommonDiff(io, gd),
                    .channel => |ch| try self.fetchChannelDiff(io, ch.id, ch.req),
                }
            }
            if (changed) self.persistState(io);
        }

        fn fetchCommonDiff(self: *Self, io: Io, gd: functions.updates.GetDifference) !void {
            ulog.info("GetDifference pts={} qts={} date={}", .{ gd.pts, gd.qts, gd.date });
            const diff_resp = self.call(io, gd) catch |err| switch (err) {
                // Dead pts/qts: getDifference can never catch up, so re-seed from
                // GetState and clear the gap instead of retrying forever.
                error.PersistentTimestampInvalid => return self.resetCommonState(io),
                else => return err,
            };
            defer diff_resp.deinit();
            const diff = diff_resp.value;
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const applied = blk: {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                const a = try self.state.applyDifference(arena.allocator(), diff);
                try self.state.peers.update(self.allocator, a.users, a.chats);
                self.recordChannelHashesLocked(a.chats);
                break :blk a;
            };
            ulog.info("applyDifference -> pts={} ups={} has_more={}", .{
                self.state.pts, applied.updates.len, applied.has_more,
            });
            try self.dispatchUpdateSlice(io, arena.allocator(), applied.updates, applied.users, applied.chats);
        }

        /// Recover from PERSISTENT_TIMESTAMP_INVALID/EMPTY: the stored pts/qts is
        /// unrecoverable (stale session, token/account change, or too long offline),
        /// so re-seed common state from updates.GetState and clear the gap. Mirrors
        /// the first-time seeding in initUpdateState.
        fn resetCommonState(self: *Self, io: Io) !void {
            ulog.warn("persistent timestamp invalid, resyncing common state via GetState", .{});
            const st_resp = try self.call(io, functions.updates.GetState{});
            defer st_resp.deinit();
            const st = st_resp.value;
            self.mb_mutex.lockUncancelable(io);
            defer self.mb_mutex.unlock(io);
            self.state.setState(st);
            self.state.getting_diff = false;
            ulog.info("GetState resync -> pts={} qts={} date={} seq={}", .{ st.pts, st.qts, st.date, st.seq });
        }

        fn fetchChannelDiff(self: *Self, io: Io, id: i64, base: functions.updates.GetChannelDifference) !void {
            var req = base;
            {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                if (self.state.peers.inputChannel(id)) |ic| {
                    req.channel = ic;
                } else {
                    _ = self.state.getting_channel_diff.remove(id);
                    ulog.warn("channel {} access_hash unknown, skipping diff", .{id});
                    return;
                }
            }
            ulog.info("GetChannelDifference channel={} pts={}", .{ id, req.pts });
            const diff_resp = self.call(io, req) catch |err| switch (err) {
                error.ChannelInvalid => {
                    self.mb_mutex.lockUncancelable(io);
                    defer self.mb_mutex.unlock(io);
                    self.state.dropChannel(id);
                    ulog.warn("channel {} invalid, dropping from diff tracking", .{id});
                    return;
                },
                else => return err,
            };
            defer diff_resp.deinit();
            const diff = diff_resp.value;
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const applied = blk: {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                const a = try self.state.applyChannelDifference(self.allocator, arena.allocator(), id, diff);
                try self.state.peers.update(self.allocator, a.users, a.chats);
                self.recordChannelHashesLocked(a.chats);
                break :blk a;
            };
            ulog.info("applyChannelDifference ch={} ups={} has_more={}", .{
                id, applied.updates.len, applied.has_more,
            });
            try self.dispatchUpdateSlice(io, arena.allocator(), applied.updates, applied.users, applied.chats);
        }

        fn persistState(self: *Self, io: Io) void {
            var aw: std.Io.Writer.Allocating = .init(self.allocator);
            defer aw.deinit();
            {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                self.state.serialize(&aw.writer) catch |e| {
                    std.log.debug("serialize state: {}", .{e});
                    return;
                };
            }
            self.opts.storage.saveUpdateState(io, self.allocator, aw.written()) catch |e|
                std.log.debug("saveUpdateState: {}", .{e});
        }

        fn authBot(self: *Self, io: Io, token: []const u8) !void {
            const auth_resp = try self.call(io, functions.auth.ImportBotAuthorization{
                .flags = 0,
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
                .bot_auth_token = token,
            });
            defer auth_resp.deinit();
            const auth = auth_resp.value;
            switch (auth) {
                .AuthAuthorization => |a| switch (a.user) {
                    .User => |u| self.bot_id = u.id,
                    else => {},
                },
                else => {},
            }
        }

        fn buildQrUrl(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
            const prefix = "tg://login?token=";
            const enc = &std.base64.url_safe_no_pad.Encoder;
            const buf = try allocator.alloc(u8, prefix.len + enc.calcSize(token.len));
            @memcpy(buf[0..prefix.len], prefix);
            _ = enc.encode(buf[prefix.len..], token);
            return buf;
        }

        fn loginQrImpl(ptr: *anyopaque, io: Io, on_token: *const fn (url: []const u8) anyerror!void) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            while (true) {
                const resp = try self.call(io, functions.auth.ExportLoginToken{
                    .api_id = self.opts.api_id,
                    .api_hash = self.opts.api_hash,
                    .except_ids = &.{},
                });
                defer resp.deinit();
                switch (resp.value) {
                    .AuthLoginToken => |t| {
                        const url = try buildQrUrl(self.allocator, t.token);
                        defer self.allocator.free(url);
                        try on_token(url);
                        const now_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
                        const now_s: i64 = @intCast(@divTrunc(now_ns, std.time.ns_per_s));
                        const secs: i64 = @max(0, @as(i64, t.expires) - now_s);
                        std.Io.sleep(io, std.Io.Duration.fromSeconds(secs), .awake) catch |e| std.log.debug("qr sleep: {}", .{e});
                    },
                    .AuthLoginTokenMigrateTo => |m| {
                        try self.importQrTokenViaDc(io, @intCast(m.dc_id), m.token);
                        return;
                    },
                    .AuthLoginTokenSuccess => return,
                }
            }
        }

        fn importQrTokenViaDc(self: *Self, io: Io, dc_id: u8, token: []const u8) !void {
            const dc = self.findDc(dc_id) orelse return error.DcNotFound;

            const mem = try self.allocator.create(Storage.Memory);
            mem.* = .{};
            errdefer {
                mem.deinit(self.allocator);
                self.allocator.destroy(mem);
            }

            const conn = try Connector.connect(io, self.allocator, .{
                .dc = dc,
                .transport = .abridged,
                .storage = mem.storage(),
                .api_id = self.opts.api_id,
                .api_hash = self.opts.api_hash,
            });
            errdefer conn.deinit();
            try conn.run(io, sub_conn_noop_handler);
            errdefer {
                conn.close(io);
                conn.join(io);
            }

            // importLoginToken on the target DC
            {
                const bytes = try codec.encodeAlloc(
                    functions.auth.ImportLoginToken{ .token = token },
                    self.allocator,
                );
                defer self.allocator.free(bytes);
                const raw = try self.callViaConnector(io, conn, bytes);
                defer self.allocator.free(raw);
                if (isRpcError(raw)) return error.RpcError;
            }

            // Export auth from target DC back to our primary DC so the primary is also authenticated.
            const primary_dc_id = if (self.primary) |p| p.dc_id else {
                conn.close(io);
                conn.join(io);
                conn.deinit();
                mem.deinit(self.allocator);
                self.allocator.destroy(mem);
                return;
            };
            var export_buf: [32]u8 = undefined;
            var ew: std.Io.Writer = .fixed(&export_buf);
            try codec.encode(functions.auth.ExportAuthorization{ .dc_id = @intCast(primary_dc_id) }, &ew);
            const export_raw = try self.callViaConnector(io, conn, ew.buffered());
            defer self.allocator.free(export_raw);

            conn.close(io);
            conn.join(io);
            conn.deinit();
            mem.deinit(self.allocator);
            self.allocator.destroy(mem);

            if (isRpcError(export_raw)) return error.AuthTransferFailed;

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            var r: std.Io.Reader = .fixed(export_raw);
            const exported = try codec.decode(types.AuthExportedAuthorization, &r, arena.allocator());

            const import_bytes = try codec.encodeAlloc(
                functions.auth.ImportAuthorization{ .id = exported.id, .bytes = exported.bytes },
                self.allocator,
            );
            defer self.allocator.free(import_bytes);
            const import_raw = try self.callRaw(io, import_bytes);
            defer self.allocator.free(import_raw);
            if (isRpcError(import_raw)) return error.AuthTransferFailed;
        }

        fn findDc(self: *const Self, dc_id: u8) ?Connector.DC {
            if (self.dc_list) |list| {
                for (list) |dc| {
                    if (dc.id == dc_id) return dc;
                }
            }
            return Connector.findDc(dc_id, self.opts.dc.test_server);
        }

        fn callRaw(self: *Self, io: Io, bytes: []const u8) ![]u8 {
            return self.callViaConnector(io, self.primary orelse return error.NotConnected, bytes);
        }

        /// Classify an `rpc_error` for the internal sync/auth path. Returns void when
        /// the error is auto-retryable and `can_retry` is true (sleeping first, e.g.
        /// for FLOOD_WAIT); otherwise maps to the Zig error the run loop expects.
        fn handleRpcError(self: *Self, io: Io, raw: []const u8, can_retry: bool) !void {
            const e = RpcError.parse(raw);
            e.log();
            if (e.migrateDc()) |dc_id| {
                self.opts.dc = self.findDc(dc_id) orelse return error.RpcError;
                return error.DcMigrate;
            }
            if (e.autoRetryDelayMs()) |ms| {
                if (!can_retry) return error.RpcError;
                if (ms > 0) std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(ms)), .awake) catch |err| std.log.debug("sleep: {}", .{err});
                return; // retry
            }
            // SESSION_PASSWORD_NEEDED is a 401 but means "needs 2FA", not a dead
            // session — isUnauthorized() already excludes it.
            if (e.isSessionPasswordNeeded()) return error.SessionPasswordNeeded;
            if (e.isUnauthorized()) return error.SessionInvalid;
            // Retryable user-input errors: surface them distinctly so callers can
            // re-prompt in place instead of tearing down the connection.
            if (e.isPhoneCodeInvalid()) return error.PhoneCodeInvalid;
            if (e.isPasswordHashInvalid()) return error.PasswordHashInvalid;
            // Channel we can't access: permanent, so the diff loop must drop it
            // rather than retry forever.
            if (e.isChannelInvalid()) return error.ChannelInvalid;
            // Persisted pts/qts is unrecoverable (stale session, token/account change,
            // or too long offline). getDifference can't recover; resync via getState.
            if (e.is("PERSISTENT_TIMESTAMP_INVALID") or e.is("PERSISTENT_TIMESTAMP_EMPTY"))
                return error.PersistentTimestampInvalid;
            return error.RpcError;
        }

        fn handleUpdate(ptr: *anyopaque, io: Io, payload: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            if (payload.len < 4) return;
            const cid = std.mem.readInt(u32, payload[0..4], .little);
            switch (cid) {
                types.Updates.cid, types.UpdatesCombined.cid => self.dispatchUpdates(io, payload) catch |err|
                    std.log.warn("update dispatch error: {}", .{err}),
                types.UpdateShort.cid => self.dispatchShort(io, payload) catch |err|
                    std.log.warn("update dispatch error: {}", .{err}),
                types.UpdateShortMessage.cid => self.dispatchShortMessage(io, payload) catch |err|
                    std.log.warn("update dispatch error: {}", .{err}),
                types.UpdateShortChatMessage.cid => self.dispatchShortChatMessage(io, payload) catch |err|
                    std.log.warn("update dispatch error: {}", .{err}),
                types.UpdatesTooLong.cid => {
                    self.mb_mutex.lockUncancelable(io);
                    self.state.getting_diff = true;
                    self.mb_mutex.unlock(io);
                    self.sync_event.set(io);
                },
                else => {},
            }
        }

        fn dispatchUpdateSlice(
            self: *Self,
            io: Io,
            arena_alloc: Allocator,
            updates: []const unions.Update,
            users: []const unions.User,
            chats: []const unions.Chat,
        ) !void {
            var entities: Entities = .{};
            for (users) |u| switch (u) {
                .User => |user| if (user.access_hash.value) |ah|
                    try entities.users.put(arena_alloc, user.id, ah),
                else => {},
            };
            for (chats) |c| switch (c) {
                .Channel => |ch| if (ch.access_hash.value) |ah|
                    try entities.channels.put(arena_alloc, ch.id, ah),
                else => {},
            };

            const ctx = self.makeContext(io, entities);

            for (updates) |u| {
                const update_cid: u32 = switch (u) {
                    inline else => |body| @TypeOf(body).cid,
                };
                inline for (handlers) |entry| {
                    if (update_cid == entry.cid) {
                        entry.dispatch(ctx, u) catch |err|
                            std.log.warn("handler error: {}", .{err});
                    }
                }
            }
        }

        /// Runs a container of updates through the State, applies peer info, then
        /// dispatches the confirmed-order updates. On gap, signals sync_event
        /// (never blocks).
        fn routeUpdates(
            self: *Self,
            io: Io,
            arena_alloc: Allocator,
            c: @import("State.zig").Container,
            users: []const unions.User,
            chats: []const unions.Chat,
        ) !void {
            var applied: []unions.Update = &.{};
            var gap = false;
            {
                self.mb_mutex.lockUncancelable(io);
                defer self.mb_mutex.unlock(io);
                self.state.peers.update(self.allocator, users, chats) catch |e|
                    std.log.debug("peer_cache: {}", .{e});
                self.recordChannelHashesLocked(chats);
                const res = self.state.process(self.allocator, arena_alloc, c) catch |e| {
                    std.log.debug("process updates: {}", .{e});
                    return;
                };
                applied = res.applied;
                gap = self.state.getting_diff or self.state.getting_channel_diff.count() > 0;
            }
            ulog.debug("routeUpdates: in={} applied={} gap={} pts={} qts={}", .{
                c.updates.len, applied.len, gap, self.state.pts, self.state.qts,
            });
            try self.dispatchUpdateSlice(io, arena_alloc, applied, users, chats);
            if (gap) self.sync_event.set(io);
        }

        /// Caller must hold mb_mutex.
        fn recordChannelHashesLocked(self: *Self, chats: []const unions.Chat) void {
            for (chats) |c| switch (c) {
                .Channel => |ch| if (ch.access_hash.value) |ah| {
                    const gop = self.state.channels.getOrPut(self.allocator, ch.id) catch return;
                    if (gop.found_existing) {
                        gop.value_ptr.access_hash = ah;
                    } else {
                        gop.value_ptr.* = .{ .pts = 0, .access_hash = ah };
                    }
                },
                else => {},
            };
        }

        fn dispatchUpdates(self: *Self, io: Io, payload: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();
            var r: std.Io.Reader = .fixed(payload[4..]);
            const cid = std.mem.readInt(u32, payload[0..4], .little);
            if (cid == types.UpdatesCombined.cid) {
                const upd = try codec.decodeStructBody(types.UpdatesCombined, &r, arena_alloc);
                try self.routeUpdates(io, arena_alloc, .{
                    .date = upd.date,
                    .seq = upd.seq,
                    .seq_start = upd.seq_start,
                    .updates = upd.updates,
                }, upd.users, upd.chats);
            } else {
                const upd = try codec.decodeStructBody(types.Updates, &r, arena_alloc);
                // The bare `updates` container has no seq_start; its single group
                // spans seq..seq, so seq_start == seq for the gap check.
                try self.routeUpdates(io, arena_alloc, .{
                    .date = upd.date,
                    .seq = upd.seq,
                    .seq_start = upd.seq,
                    .updates = upd.updates,
                }, upd.users, upd.chats);
            }
        }

        fn dispatchShort(self: *Self, io: Io, payload: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();
            var r: std.Io.Reader = .fixed(payload[4..]);
            const upd = try codec.decodeStructBody(types.UpdateShort, &r, arena_alloc);
            const updates = [_]unions.Update{upd.update};
            try self.routeUpdates(io, arena_alloc, .{ .date = upd.date, .updates = &updates }, &.{}, &.{});
        }

        /// Synthesize an `UpdateNewMessage` from a decoded short(-chat)-message and
        /// route it. `short` carries the shared message fields; `from_id`/`peer_id`
        /// differ between the user and chat variants and are supplied by the caller.
        fn routeShortMessage(
            self: *Self,
            io: Io,
            arena_alloc: Allocator,
            short: anytype,
            from_id: @FieldType(types.Message, "from_id"),
            peer_id: @FieldType(types.Message, "peer_id"),
        ) !void {
            const msg = types.Message{
                .id = short.id,
                .out = short.out,
                .mentioned = short.mentioned,
                .media_unread = short.media_unread,
                .silent = short.silent,
                .from_id = from_id,
                .peer_id = peer_id,
                .date = short.date,
                .message = short.message,
                .fwd_from = short.fwd_from,
                .via_bot_id = short.via_bot_id,
                .reply_to = short.reply_to,
                .entities = short.entities,
                .ttl_period = short.ttl_period,
            };
            const updates = [_]unions.Update{.{ .UpdateNewMessage = .{
                .message = .{ .Message = msg },
                .pts = short.pts,
                .pts_count = short.pts_count,
            } }};
            try self.routeUpdates(io, arena_alloc, .{ .date = short.date, .updates = &updates }, &.{}, &.{});
        }

        fn dispatchShortMessage(self: *Self, io: Io, payload: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();
            var r: std.Io.Reader = .fixed(payload[4..]);
            const short = try codec.decodeStructBody(types.UpdateShortMessage, &r, arena_alloc);
            try self.routeShortMessage(
                io,
                arena_alloc,
                short,
                if (short.out.value != null) .none else .{ .value = .{ .PeerUser = .{ .user_id = short.user_id } } },
                .{ .PeerUser = .{ .user_id = short.user_id } },
            );
        }

        fn dispatchShortChatMessage(self: *Self, io: Io, payload: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const arena_alloc = arena.allocator();
            var r: std.Io.Reader = .fixed(payload[4..]);
            const short = try codec.decodeStructBody(types.UpdateShortChatMessage, &r, arena_alloc);
            try self.routeShortMessage(
                io,
                arena_alloc,
                short,
                .{ .value = .{ .PeerUser = .{ .user_id = short.from_id } } },
                .{ .PeerChat = .{ .chat_id = short.chat_id } },
            );
        }
    };
}

pub const nextRandomId = codec.nextRandomId;

fn initRandomCounter(io: Io) !void {
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    codec.initRandom(csprng.random().int(i64));
}

fn wrapInit(allocator: Allocator, api_id: i32, query_bytes: []const u8) ![]u8 {
    const ser = @import("codec").serialize;
    var hdr: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&hdr);
    try w.writeInt(u32, functions.InvokeWithLayer.cid, .little);
    try w.writeInt(i32, functions.layer, .little);
    try w.writeInt(u32, functions.InitConnection.cid, .little);
    try w.writeInt(i32, 0, .little);
    try ser.int(&w, api_id);
    try ser.string(&w, "tz");
    try ser.string(&w, "Zig/0.16");
    try ser.string(&w, "0.1");
    try ser.string(&w, "en");
    try ser.string(&w, "");
    try ser.string(&w, "en");
    const h = w.buffered();
    const out = try allocator.alloc(u8, h.len + query_bytes.len);
    @memcpy(out[0..h.len], h);
    @memcpy(out[h.len..], query_bytes);
    return out;
}
