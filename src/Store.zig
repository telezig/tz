//! Store — message / dialog / peer persistence interface.
//!
//! Mirrors `Storage` (session/update-state persistence) but for the message
//! domain. The tz core only depends on this vtable; concrete backends live
//! outside core (e.g. `Store.Sqlite` in `src/db/`) so core never links sqlite.
//!
//! All methods take `io` (an `std.Io` handle for sync native I/O) plus an
//! allocator for any temporary/returned allocations. Callers own returned
//! slices (freed with the same allocator).

const Store = @This();
const std = @import("std");
const Io = std.Io;

/// A normalized message row suitable for persistence.
pub const MessageRow = struct {
    id: i64,
    peer_id: i64,
    from_id: i64 = 0, // 0 when unknown
    date: i64,
    message: []const u8,
    out: bool = false,
    flags: u32 = 0,
    media_type: ?[]const u8 = null,
    media_data: ?[]const u8 = null,
};

/// A normalized peer row (entity cache: id -> access_hash + metadata).
pub const PeerRow = struct {
    id: i64,
    access_hash: i64,
    peer_type: []const u8, // "user" | "chat" | "channel"
    username: ?[]const u8 = null,
    title: ?[]const u8 = null,
    updated_at: i64,
};

/// A normalized dialog row.
pub const DialogRow = struct {
    peer_id: i64,
    top_message_id: i64 = 0,
    unread_count: i64 = 0,
    draft: ?[]const u8 = null,
    updated_at: i64,
};

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    /// Upsert one message (INSERT OR REPLACE on id). Borrowed slices are
    /// copied by the backend before returning.
    upsertMessage: *const fn (*anyopaque, Io, std.mem.Allocator, MessageRow) anyerror!void,
    /// Query the most recent `limit` messages for a peer, newest first.
    /// Caller owns the returned slice; rows' slices borrow from it.
    queryMessages: *const fn (*anyopaque, Io, std.mem.Allocator, peer_id: i64, limit: u32) anyerror![]MessageRow,
    /// Upsert one peer entity.
    upsertPeer: *const fn (*anyopaque, Io, std.mem.Allocator, PeerRow) anyerror!void,
    /// Upsert one dialog.
    upsertDialog: *const fn (*anyopaque, Io, std.mem.Allocator, DialogRow) anyerror!void,
    /// Persist an opaque key/value (e.g. pts/qts bookkeeping). Replaces.
    putKv: *const fn (*anyopaque, Io, std.mem.Allocator, key: []const u8, value: []const u8) anyerror!void,
};

pub fn upsertMessage(self: Store, io: Io, gpa: std.mem.Allocator, row: MessageRow) !void {
    return self.vtable.upsertMessage(self.ptr, io, gpa, row);
}
pub fn queryMessages(self: Store, io: Io, gpa: std.mem.Allocator, peer_id: i64, limit: u32) ![]MessageRow {
    return self.vtable.queryMessages(self.ptr, io, gpa, peer_id, limit);
}
pub fn upsertPeer(self: Store, io: Io, gpa: std.mem.Allocator, row: PeerRow) !void {
    return self.vtable.upsertPeer(self.ptr, io, gpa, row);
}
pub fn upsertDialog(self: Store, io: Io, gpa: std.mem.Allocator, row: DialogRow) !void {
    return self.vtable.upsertDialog(self.ptr, io, gpa, row);
}
pub fn putKv(self: Store, io: Io, gpa: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    return self.vtable.putKv(self.ptr, io, gpa, key, value);
}

/// No-op store: the client can hold a Store without persisting anything.
/// Useful as the default so core behavior is unchanged when no store is set.
pub const Null = struct {
    pub fn store(self: *Null) Store {
        _ = self;
        return .{ .ptr = undefined, .vtable = &vtable };
    }
    const vtable = Store.VTable{
        .upsertMessage = nullUpsertMessage,
        .queryMessages = nullQueryMessages,
        .upsertPeer = nullUpsertPeer,
        .upsertDialog = nullUpsertDialog,
        .putKv = nullPutKv,
    };
    fn nullUpsertMessage(_: *anyopaque, _: Io, _: std.mem.Allocator, _: MessageRow) anyerror!void {}
    fn nullQueryMessages(_: *anyopaque, _: Io, _: std.mem.Allocator, _: i64, _: u32) anyerror![]MessageRow {
        return &.{};
    }
    fn nullUpsertPeer(_: *anyopaque, _: Io, _: std.mem.Allocator, _: PeerRow) anyerror!void {}
    fn nullUpsertDialog(_: *anyopaque, _: Io, _: std.mem.Allocator, _: DialogRow) anyerror!void {}
    fn nullPutKv(_: *anyopaque, _: Io, _: std.mem.Allocator, _: []const u8, _: []const u8) anyerror!void {}
};

test "Null store roundtrip" {
    var n = Null{};
    const s = n.store();
    try s.upsertMessage(std.Io.failing, std.testing.allocator, .{
        .id = 1,
        .peer_id = 42,
        .date = 1700000000,
        .message = "hi",
    });
    const rows = try s.queryMessages(std.Io.failing, std.testing.allocator, 42, 10);
    try std.testing.expectEqual(@as(usize, 0), rows.len);
}
