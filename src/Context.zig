const Context = @This();
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const types = @import("types");
const unions = @import("unions");
const functions = @import("functions");
const State = @import("State.zig");
const Store = @import("store");

client: *anyopaque,
io: Io,
allocator: Allocator,
api_id: i32,
api_hash: []const u8,
entities: Entities,
peer_cache: *State.PeerCache,
mb_mutex: *std.Io.Mutex,
/// Message-history persistence backend (same instance as ClientOptions.store).
/// Handlers can read/write history through it; null when no store configured.
store: ?Store = null,
callFn: *const fn (client: *anyopaque, io: Io, bytes: []const u8) anyerror![]u8,
/// Like callFn but routes FILE_MIGRATE to a sub-connection automatically.
callFileFn: *const fn (client: *anyopaque, io: Io, bytes: []const u8) anyerror![]u8,
/// Routes to a CDN DC sub-connection (no account auth required).
callCdnFn: *const fn (client: *anyopaque, io: Io, dc_id: i32, bytes: []const u8) anyerror![]u8,
loginQrFn: *const fn (client: *anyopaque, io: Io, on_token: *const fn (url: []const u8) anyerror!void) anyerror!void,
/// Parallelism for file download/upload. See ClientOptions.file_workers.
file_workers: usize = 4,

/// Encode `request`, send it through `callFn`, and return the owned raw response
/// bytes. Caller frees with `self.allocator.free`.
fn invoke(self: Context, callFn: anytype, request: anytype) ![]u8 {
    const bytes = try codec.encodeAlloc(request, self.allocator);
    defer self.allocator.free(bytes);
    return callFn(self.client, self.io, bytes);
}

/// Send a TL request and return the decoded response. caller owns it; free with resp.deinit().
pub fn call(self: Context, request: anytype) !Response(@TypeOf(request).Response) {
    const raw = try self.invoke(self.callFn, request);
    defer self.allocator.free(raw);
    return decodeOwned(@TypeOf(request).Response, raw, self.allocator);
}

/// Send a TL request and discard the response.
pub fn exec(self: Context, request: anytype) !void {
    self.allocator.free(try self.invoke(self.callFn, request));
}

/// Like call, but routes FILE_MIGRATE errors to a sub-connection automatically.
pub fn callFile(self: Context, request: anytype) !Response(@TypeOf(request).Response) {
    const raw = try self.invoke(self.callFileFn, request);
    defer self.allocator.free(raw);
    return decodeOwned(@TypeOf(request).Response, raw, self.allocator);
}

/// QR login. calls on_token with a `tg://login?token=...` url on each token refresh.
/// Blocks until approved.
pub fn loginQr(self: Context, on_token: *const fn (url: []const u8) anyerror!void) !void {
    return self.loginQrFn(self.client, self.io, on_token);
}

/// Send a request to a CDN DC sub-connection (no account auth required).
pub fn callCdn(self: Context, dc_id: i32, request: anytype) !Response(@TypeOf(request).Response) {
    const bytes = try codec.encodeAlloc(request, self.allocator);
    defer self.allocator.free(bytes);
    const raw = try self.callCdnFn(self.client, self.io, dc_id, bytes);
    defer self.allocator.free(raw);
    return decodeOwned(@TypeOf(request).Response, raw, self.allocator);
}

/// Like exec, but routes FILE_MIGRATE errors to a sub-connection automatically.
pub fn execFile(self: Context, request: anytype) !void {
    self.allocator.free(try self.invoke(self.callFileFn, request));
}

/// Look up a peer by user/channel id from the session cache. null if not seen yet.
pub fn resolvePeer(self: Context, id: i64) ?unions.InputPeer {
    self.mb_mutex.lockUncancelable(self.io);
    defer self.mb_mutex.unlock(self.io);
    return self.peer_cache.inputPeer(id);
}

/// Look up a channel by id from the session cache. null if not seen yet.
pub fn resolveInputChannel(self: Context, id: i64) ?unions.InputChannel {
    self.mb_mutex.lockUncancelable(self.io);
    defer self.mb_mutex.unlock(self.io);
    return self.peer_cache.inputChannel(id);
}

pub fn resolveUsername(self: Context, username: []const u8) !unions.InputPeer {
    const raw = std.mem.trimStart(u8, username, "@");
    if (raw.len == 0 or raw.len > 64) return error.InvalidUsername;
    var buf: [64]u8 = undefined;
    const name = std.ascii.lowerString(buf[0..raw.len], raw);

    {
        self.mb_mutex.lockUncancelable(self.io);
        defer self.mb_mutex.unlock(self.io);
        if (self.peer_cache.lookupUsername(name)) |id|
            if (self.peer_cache.inputPeer(id)) |ip| return ip;
    }

    const r = try self.call(functions.contacts.ResolveUsername{ .username = name });
    defer r.deinit();

    self.mb_mutex.lockUncancelable(self.io);
    defer self.mb_mutex.unlock(self.io);
    try self.peer_cache.update(self.allocator, r.value.users, r.value.chats);
    const id: i64 = switch (r.value.peer) {
        .PeerUser => |p| p.user_id,
        .PeerChannel => |p| p.channel_id,
        .PeerChat => |p| p.chat_id,
    };
    return self.peer_cache.inputPeer(id) orelse error.PeerNotFound;
}

/// Owned decode result. Free with deinit().
pub fn Response(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: @This()) void {
            const gpa = self.arena.child_allocator;
            self.arena.deinit();
            gpa.destroy(self.arena);
        }
    };
}

pub const Entities = struct {
    users: std.AutoHashMapUnmanaged(i64, i64) = .empty,
    channels: std.AutoHashMapUnmanaged(i64, i64) = .empty,

    pub fn accessHash(self: *const Entities, user_id: i64) ?i64 {
        return self.users.get(user_id);
    }

    pub fn channelAccessHash(self: *const Entities, channel_id: i64) ?i64 {
        return self.channels.get(channel_id);
    }

    pub fn inputUser(self: *const Entities, user_id: i64) ?unions.InputUser {
        const ah = self.users.get(user_id) orelse return null;
        return .{ .InputUser = .{ .user_id = user_id, .access_hash = ah } };
    }

    pub fn inputChannel(self: *const Entities, channel_id: i64) ?unions.InputChannel {
        const ah = self.channels.get(channel_id) orelse return null;
        return .{ .InputChannel = .{ .channel_id = channel_id, .access_hash = ah } };
    }
};

pub fn decodeOwned(comptime T: type, raw: []const u8, gpa: Allocator) !Response(T) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    var r: std.Io.Reader = .fixed(raw);
    const value = try codec.decode(T, &r, arena.allocator());
    return .{ .arena = arena, .value = value };
}
