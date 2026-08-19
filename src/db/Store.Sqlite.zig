//! SQLite-backed Store implementation.
//!
//! Lives in the optional `tz_db` module (not core) so that only consumers who
//! want sqlite persistence link sqlite3.c. Uses the shared schema from
//! `schema.zig` (messages / peers / dialogs / kv_meta).
const std = @import("std");
const Store = @import("../Store.zig");
const Database = @import("Database.zig").Database;
const Statement = @import("Database.zig").Statement;
const StepResult = @import("Database.zig").StepResult;

pub const Sqlite = struct {
    db: Database,

    pub fn init(path: [:0]const u8) !Sqlite {
        var db = try Database.open(path);
        errdefer db.close();
        try initTables(&db);
        return .{ .db = db };
    }

    pub fn deinit(self: *Sqlite) void {
        self.db.close();
    }

    pub fn store(self: *Sqlite) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn initTables(db: *Database) !void {
        // Same shape as src/db/schema.zig but self-contained (schema.zig may
        // diverge later; keep this POC in sync).
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS messages (
            \\    id INTEGER PRIMARY KEY,
            \\    peer_id INTEGER NOT NULL,
            \\    from_id INTEGER NOT NULL DEFAULT 0,
            \\    date INTEGER NOT NULL,
            \\    message TEXT NOT NULL,
            \\    media_type TEXT,
            \\    media_data BLOB,
            \\    out INTEGER NOT NULL DEFAULT 0,
            \\    flags INTEGER NOT NULL DEFAULT 0
            \\);
        );
        try db.exec(
            \\CREATE INDEX IF NOT EXISTS idx_messages_peer_date
            \\ON messages(peer_id, date DESC);
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS peers (
            \\    id INTEGER PRIMARY KEY,
            \\    access_hash INTEGER NOT NULL,
            \\    type TEXT NOT NULL,
            \\    username TEXT,
            \\    title TEXT,
            \\    updated_at INTEGER NOT NULL
            \\);
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS dialogs (
            \\    peer_id INTEGER PRIMARY KEY,
            \\    top_message_id INTEGER NOT NULL DEFAULT 0,
            \\    unread_count INTEGER NOT NULL DEFAULT 0,
            \\    draft TEXT,
            \\    updated_at INTEGER NOT NULL
            \\);
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS kv_meta (
            \\    key TEXT PRIMARY KEY,
            \\    value TEXT NOT NULL
            \\);
        );
    }

    // --- Store vtable impls ---

    fn upsertMessage(ptr: *anyopaque, _: std.Io, gpa: std.mem.Allocator, row: Store.MessageRow) anyerror!void {
        const self: *Sqlite = @ptrCast(@alignCast(ptr));
        _ = gpa;
        const stmt = try self.db.prepare(
            \\INSERT INTO messages (id, peer_id, from_id, date, message, media_type, media_data, out, flags)
            \\VALUES (?,?,?,?,?,?,?,?,?)
            \\ON CONFLICT(id) DO UPDATE SET
            \\  peer_id=excluded.peer_id, from_id=excluded.from_id, date=excluded.date,
            \\  message=excluded.message, media_type=excluded.media_type,
            \\  media_data=excluded.media_data, out=excluded.out, flags=excluded.flags;
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, row.id);
        try stmt.bindInt64(2, row.peer_id);
        try stmt.bindInt64(3, row.from_id);
        try stmt.bindInt64(4, row.date);
        try stmt.bindText(5, row.message);
        if (row.media_type) |mt| try stmt.bindText(6, mt) else try stmt.bindNull(6);
        if (row.media_data) |md| try stmt.bindBlob(7, md) else try stmt.bindNull(7);
        try stmt.bindInt(8, if (row.out) 1 else 0);
        try stmt.bindInt64(9, row.flags);
        try expectDone(try stmt.step());
    }

    fn queryMessages(ptr: *anyopaque, _: std.Io, gpa: std.mem.Allocator, peer_id: i64, limit: u32) anyerror![]Store.MessageRow {
        const self: *Sqlite = @ptrCast(@alignCast(ptr));
        const stmt = try self.db.prepare(
            \\SELECT id, peer_id, from_id, date, message, media_type, media_data, out, flags
            \\FROM messages WHERE peer_id = ? ORDER BY date DESC, id DESC LIMIT ?;
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, peer_id);
        try stmt.bindInt(2, @intCast(limit));

        var rows = std.ArrayListUnmanaged(Store.MessageRow){};
        errdefer {
            for (rows.items) |r| {
                gpa.free(r.message);
                if (r.media_type) |mt| gpa.free(mt);
                if (r.media_data) |md| gpa.free(md);
            }
            rows.deinit(gpa);
        }
        while (try stmt.step() == StepResult.row) {
            const m = stmt.columnText(5);
            const mt = stmt.columnText(6);
            const md = stmt.columnBlob(7);
            try rows.append(gpa, .{
                .id = stmt.columnInt64(0),
                .peer_id = stmt.columnInt64(1),
                .from_id = stmt.columnInt64(2),
                .date = stmt.columnInt64(3),
                .message = try gpa.dupe(u8, m),
                .media_type = if (mt.len > 0) try gpa.dupe(u8, mt) else null,
                .media_data = if (md.len > 0) try gpa.dupe(u8, md) else null,
                .out = stmt.columnInt(7) != 0,
                .flags = @intCast(stmt.columnInt64(8)),
            });
        }
        return rows.toOwnedSlice(gpa);
    }

    fn upsertPeer(ptr: *anyopaque, _: std.Io, _: std.mem.Allocator, row: Store.PeerRow) anyerror!void {
        const self: *Sqlite = @ptrCast(@alignCast(ptr));
        const stmt = try self.db.prepare(
            \\INSERT INTO peers (id, access_hash, type, username, title, updated_at)
            \\VALUES (?,?,?,?,?,?)
            \\ON CONFLICT(id) DO UPDATE SET
            \\  access_hash=excluded.access_hash, type=excluded.type,
            \\  username=excluded.username, title=excluded.title,
            \\  updated_at=excluded.updated_at;
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, row.id);
        try stmt.bindInt64(2, row.access_hash);
        try stmt.bindText(3, row.peer_type);
        if (row.username) |u| try stmt.bindText(4, u) else try stmt.bindNull(4);
        if (row.title) |t| try stmt.bindText(5, t) else try stmt.bindNull(5);
        try stmt.bindInt64(6, row.updated_at);
        try expectDone(try stmt.step());
    }

    fn upsertDialog(ptr: *anyopaque, _: std.Io, _: std.mem.Allocator, row: Store.DialogRow) anyerror!void {
        const self: *Sqlite = @ptrCast(@alignCast(ptr));
        const stmt = try self.db.prepare(
            \\INSERT INTO dialogs (peer_id, top_message_id, unread_count, draft, updated_at)
            \\VALUES (?,?,?,?,?)
            \\ON CONFLICT(peer_id) DO UPDATE SET
            \\  top_message_id=excluded.top_message_id, unread_count=excluded.unread_count,
            \\  draft=excluded.draft, updated_at=excluded.updated_at;
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, row.peer_id);
        try stmt.bindInt64(2, row.top_message_id);
        try stmt.bindInt64(3, row.unread_count);
        if (row.draft) |d| try stmt.bindText(4, d) else try stmt.bindNull(4);
        try stmt.bindInt64(5, row.updated_at);
        try expectDone(try stmt.step());
    }

    fn putKv(ptr: *anyopaque, _: std.Io, _: std.mem.Allocator, key: []const u8, value: []const u8) anyerror!void {
        const self: *Sqlite = @ptrCast(@alignCast(ptr));
        const stmt = try self.db.prepare(
            \\INSERT INTO kv_meta (key, value) VALUES (?,?)
            \\ON CONFLICT(key) DO UPDATE SET value=excluded.value;
        );
        defer stmt.finalize();
        try stmt.bindText(1, key);
        try stmt.bindText(2, value);
        try expectDone(try stmt.step());
    }

    const vtable = Store.VTable{
        .upsertMessage = upsertMessage,
        .queryMessages = queryMessages,
        .upsertPeer = upsertPeer,
        .upsertDialog = upsertDialog,
        .putKv = putKv,
    };

    fn expectDone(r: StepResult) !void {
        if (r != StepResult.done) return error.SqliteStepFailed;
    }
};

test "Sqlite store roundtrip" {
    const gpa = std.testing.allocator;
    var s = try Sqlite.init(":memory:");
    defer s.deinit();
    const store = s.store();

    try store.upsertMessage(std.Io.failing, gpa, .{
        .id = 1,
        .peer_id = 42,
        .from_id = 7,
        .date = 1700000000,
        .message = "hello sqlite",
        .out = false,
        .flags = 0,
    });
    try store.upsertMessage(std.Io.failing, gpa, .{
        .id = 2,
        .peer_id = 42,
        .from_id = 8,
        .date = 1700000001,
        .message = "second",
        .out = true,
        .flags = 3,
    });
    // upsert replaces
    try store.upsertMessage(std.Io.failing, gpa, .{
        .id = 1,
        .peer_id = 42,
        .from_id = 9,
        .date = 1700000000,
        .message = "edited",
        .out = false,
        .flags = 0,
    });

    const rows = try store.queryMessages(std.Io.failing, gpa, 42, 10);
    defer {
        for (rows) |r| {
            gpa.free(r.message);
            if (r.media_type) |mt| gpa.free(mt);
            if (r.media_data) |md| gpa.free(md);
        }
        gpa.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    // newest first
    try std.testing.expectEqual(@as(i64, 2), rows[0].id);
    try std.testing.expectEqualStrings("second", rows[0].message);
    try std.testing.expect(rows[0].out);
    try std.testing.expectEqual(@as(i64, 1), rows[1].id);
    try std.testing.expectEqualStrings("edited", rows[1].message);
}

test "Sqlite store peer + dialog + kv" {
    const gpa = std.testing.allocator;
    var s = try Sqlite.init(":memory:");
    defer s.deinit();
    const store = s.store();

    try store.upsertPeer(std.Io.failing, gpa, .{
        .id = 100,
        .access_hash = 123456,
        .peer_type = "user",
        .username = "alice",
        .updated_at = 1700000000,
    });
    try store.upsertDialog(std.Io.failing, gpa, .{
        .peer_id = 100,
        .top_message_id = 5,
        .unread_count = 2,
        .updated_at = 1700000001,
    });
    try store.putKv(std.Io.failing, gpa, "pts", "1234");

    // Re-open the same in-memory db? :memory: is per-connection, so verify via
    // a second Sqlite over a temp file instead.
    const path = "/tmp/tz_store_test.db";
    std.fs.cwd().deleteFile(path) catch {};
    var f = try Sqlite.init(path);
    defer {
        f.deinit();
        std.fs.cwd().deleteFile(path) catch {};
    }
    const fs = f.store();
    try fs.upsertMessage(std.Io.failing, gpa, .{
        .id = 9,
        .peer_id = 42,
        .date = 1700000002,
        .message = "persisted",
    });
    const rows = try fs.queryMessages(std.Io.failing, gpa, 42, 10);
    defer {
        for (rows) |r| {
            gpa.free(r.message);
            if (r.media_type) |mt| gpa.free(mt);
            if (r.media_data) |md| gpa.free(md);
        }
        gpa.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqualStrings("persisted", rows[0].message);
}
