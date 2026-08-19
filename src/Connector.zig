const Connector = @This();
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Transport = @import("Transport.zig");
const Session = @import("mtproto/Session.zig");
const Storage = @import("Storage.zig");
const auth_key = @import("mtproto/auth_key.zig");
const mtproto = @import("mtproto.zig");

pub const DC = struct {
    id: u8,
    addr: Io.net.IpAddress,
    test_server: bool,
};

pub const default_dcs: []const DC = &.{
    .{ .id = 1, .addr = Io.net.IpAddress.parseIp4("149.154.175.53", 443) catch @panic("bad ip"), .test_server = false },
    .{ .id = 2, .addr = Io.net.IpAddress.parseIp4("149.154.167.41", 443) catch @panic("bad ip"), .test_server = false },
    .{ .id = 3, .addr = Io.net.IpAddress.parseIp4("149.154.175.100", 443) catch @panic("bad ip"), .test_server = false },
    .{ .id = 4, .addr = Io.net.IpAddress.parseIp4("149.154.167.91", 443) catch @panic("bad ip"), .test_server = false },
    .{ .id = 5, .addr = Io.net.IpAddress.parseIp4("91.108.56.191", 443) catch @panic("bad ip"), .test_server = false },
    .{ .id = 1, .addr = Io.net.IpAddress.parseIp4("149.154.175.10", 443) catch @panic("bad ip"), .test_server = true },
    .{ .id = 2, .addr = Io.net.IpAddress.parseIp4("149.154.167.40", 443) catch @panic("bad ip"), .test_server = true },
    .{ .id = 3, .addr = Io.net.IpAddress.parseIp4("149.154.175.117", 443) catch @panic("bad ip"), .test_server = true },
};

pub fn findDc(dc_id: u8, test_server: bool) ?DC {
    for (default_dcs) |dc| {
        if (dc.id == dc_id and dc.test_server == test_server) return dc;
    }
    return null;
}

/// Internal MtProto handler: bridges generic MtProto into Connector's update_group.
const MtpHandler = struct {
    connector: *Connector,

    pub fn onUpdate(self: *MtpHandler, io: Io, payload: []const u8) void {
        // OOM here drops one update; pts/qts gap detection recovers it via getDifference.
        const owned = self.connector.allocator.dupe(u8, payload) catch |e| {
            std.log.warn("update dropped (dupe failed): {}", .{e});
            return;
        };
        self.connector.update_group.concurrent(
            io,
            Connector.runUpdate,
            .{ self.connector, io, owned },
        ) catch {
            self.connector.allocator.free(owned);
        };
    }
};

const MtpImpl = mtproto.MtProto(MtpHandler);

pub const Options = struct {
    dc: DC,
    transport: Transport.Mode = .abridged,
    storage: Storage,
    api_id: i32,
    api_hash: []const u8,
};

/// Vtable-based update callback. Passed in from Client.
pub const UpdateHandler = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        handle: *const fn (ptr: *anyopaque, io: Io, payload: []const u8) void,
    };
    pub fn handle(self: UpdateHandler, io: Io, payload: []const u8) void {
        self.vtable.handle(self.ptr, io, payload);
    }
};

// Fields
allocator: Allocator,
mtp: *MtpImpl,
mtp_handler: MtpHandler,
update_group: std.Io.Group = .init,
update_handler: UpdateHandler,
initialized: bool = false,
is_home: bool = false,
api_id: i32,
api_hash: []const u8,
storage: Storage,
dc_id: u8,

/// Manages a single MTProto connection: connects, authenticates the transport,
/// dispatches updates asynchronously, and exposes call() for RPC.
pub fn connect(io: Io, allocator: Allocator, opts: Options) !*Connector {
    const stream = try opts.dc.addr.connect(io, .{ .mode = .stream });
    var conn = Transport.init(stream, opts.transport);

    var loaded_is_home = false;
    const auth_key_result = blk: {
        if (try opts.storage.load(io, allocator, opts.dc.id)) |saved| {
            if (saved.dc_id != 0 and saved.dc_id == opts.dc.id) {
                std.log.info("loaded existing session (dc={})", .{saved.dc_id});
                loaded_is_home = saved.is_home;
                break :blk auth_key.Result{
                    .auth_key = saved.auth_key,
                    .auth_key_id = saved.auth_key_id,
                    .server_salt = saved.server_salt,
                    .time_offset = 0,
                };
            }
            if (saved.dc_id != 0) {
                std.log.info("session dc={} != target dc={}, re-doing DH", .{ saved.dc_id, opts.dc.id });
            }
        }
        std.log.info("performing DH key exchange", .{});
        const result = try auth_key.perform(&conn, io, allocator);
        std.log.info("DH key exchange complete", .{});
        try opts.storage.save(io, allocator, .{
            .auth_key = result.auth_key,
            .auth_key_id = result.auth_key_id,
            .server_salt = result.server_salt,
            .dc_id = opts.dc.id,
        });
        break :blk result;
    };

    const mtp_session = Session.init(
        auth_key_result.auth_key,
        auth_key_result.auth_key_id,
        auth_key_result.server_salt,
        Session.ioEntropy(io),
    );

    const self = try allocator.create(Connector);
    self.* = .{
        .allocator = allocator,
        // SAFETY: mtp is initialized by Connector.connect before any use
        .mtp = undefined,
        .mtp_handler = .{ .connector = self },
        // SAFETY: update_handler is set by Connector.run before any update is dispatched
        .update_handler = undefined,
        .api_id = opts.api_id,
        .api_hash = opts.api_hash,
        .storage = opts.storage,
        .dc_id = opts.dc.id,
        .is_home = loaded_is_home,
    };
    self.mtp = try MtpImpl.init(allocator, conn, mtp_session, &self.mtp_handler);
    return self;
}

pub fn deinit(self: *Connector) void {
    self.mtp.deinit();
    self.allocator.destroy(self);
}

/// Start the MtProto loops. Must be called before call().
pub fn run(self: *Connector, io: Io, handler: UpdateHandler) !void {
    self.update_handler = handler;
    try self.mtp.run(io);
}

/// Threadsafe. Signal connection to close.
pub fn close(self: *Connector, io: Io) void {
    self.mtp.close(io);
}

/// Block until all loops exit, then drain update_group.
pub fn join(self: *Connector, io: Io) void {
    self.mtp.join();
    self.update_group.cancel(io);
}

/// Persist current session (with latest server_salt) back to storage.
pub fn saveSession(self: *Connector, io: Io) void {
    const s = &self.mtp.session;
    self.storage.save(io, self.allocator, .{
        .auth_key = s.auth_key,
        .auth_key_id = s.auth_key_id,
        .server_salt = s.server_salt,
        .dc_id = self.dc_id,
        .is_home = self.is_home,
    }) catch |err| std.log.warn("failed to save session: {}", .{err});
}

/// Send raw TL bytes, return raw response bytes (caller frees).
pub fn call(self: *Connector, io: Io, request: []const u8) ![]u8 {
    return self.mtp.call(io, request);
}

/// Whether this connection has sent initConnection yet.
pub fn isInitialized(self: *Connector) bool {
    return self.initialized;
}

pub fn setInitialized(self: *Connector) void {
    self.initialized = true;
}

fn runUpdate(self: *Connector, io: Io, payload: []u8) !void {
    defer self.allocator.free(payload);
    self.update_handler.handle(io, payload);
}
