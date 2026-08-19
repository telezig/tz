const std = @import("std");
const Database = @import("Database.zig").Database;

pub const Schema = struct {
    pub fn initTables(db: *const Database) !void {
        // Messages table
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS messages (
            \\    id INTEGER PRIMARY KEY,
            \\    peer_id INTEGER NOT NULL,
            \\    from_id INTEGER NOT NULL,
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
            \\ON messages(peer_id, date);
        );

        // Peers table (Entity / AccessHash cache)
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

        // Dialogs table
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS dialogs (
            \\    peer_id INTEGER PRIMARY KEY,
            \\    top_message_id INTEGER NOT NULL DEFAULT 0,
            \\    unread_count INTEGER NOT NULL DEFAULT 0,
            \\    draft TEXT,
            \\    updated_at INTEGER NOT NULL
            \\);
        );

        // Key-Value metadata table (e.g. pts, qts, seq, date, bot_id)
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS kv_meta (
            \\    key TEXT PRIMARY KEY,
            \\    value TEXT NOT NULL
            \\);
        );

        // FTS5 Full-Text Search virtual table for messages
        try db.exec(
            \\CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
            \\    message,
            \\    content='messages',
            \\    content_rowid='id'
            \\);
        );
    }
};
