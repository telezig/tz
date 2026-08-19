const std = @import("std");

pub const c = @import("db/c.zig").c;
pub const Database = @import("db/Database.zig").Database;
pub const Statement = @import("db/Database.zig").Statement;
pub const StepResult = @import("db/Database.zig").StepResult;
pub const Schema = @import("db/schema.zig").Schema;

test "in-memory sqlite test" {
    const db = try Database.open(":memory:");
    var mutable_db = db;
    defer mutable_db.close();

    try Schema.initTables(&mutable_db);

    // Insert a peer
    {
        const stmt = try mutable_db.prepare(
            \\INSERT INTO peers (id, access_hash, type, username, title, updated_at)
            \\VALUES (?, ?, ?, ?, ?, ?);
        );
        var mutable_stmt = stmt;
        defer mutable_stmt.finalize();

        try mutable_stmt.bindInt64(1, 123456789);
        try mutable_stmt.bindInt64(2, 9876543210);
        try mutable_stmt.bindText(3, "user");
        try mutable_stmt.bindText(4, "test_bot");
        try mutable_stmt.bindText(5, "Test Bot");
        try mutable_stmt.bindInt64(6, 1700000000);

        const step_res = try mutable_stmt.step();
        try std.testing.expectEqual(StepResult.done, step_res);
    }

    // Insert 1000 messages in a transaction (benchmark)
    {
        try mutable_db.beginTransaction();
        const stmt = try mutable_db.prepare(
            \\INSERT INTO messages (id, peer_id, from_id, date, message, out, flags)
            \\VALUES (?, ?, ?, ?, ?, ?, ?);
        );
        var mutable_stmt = stmt;
        defer mutable_stmt.finalize();

        var i: i32 = 1;
        while (i <= 1000) : (i += 1) {
            try mutable_stmt.reset();
            try mutable_stmt.bindInt(1, i);
            try mutable_stmt.bindInt64(2, 123456789);
            try mutable_stmt.bindInt64(3, 123456789);
            try mutable_stmt.bindInt64(4, 1700000000 + i);
            try mutable_stmt.bindText(5, "Hello Telegram message from Zig SQLite");
            try mutable_stmt.bindInt(6, 0);
            try mutable_stmt.bindInt(7, 0);

            const res = try mutable_stmt.step();
            try std.testing.expectEqual(StepResult.done, res);
        }
        try mutable_db.commit();
    }

    // Query count
    {
        const stmt = try mutable_db.prepare("SELECT COUNT(*) FROM messages WHERE peer_id = ?;");
        var mutable_stmt = stmt;
        defer mutable_stmt.finalize();

        try mutable_stmt.bindInt64(1, 123456789);
        const res = try mutable_stmt.step();
        try std.testing.expectEqual(StepResult.row, res);
        const count = mutable_stmt.columnInt(0);
        try std.testing.expectEqual(@as(i32, 1000), count);
    }
}
