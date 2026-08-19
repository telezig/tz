//! WebAssembly entry point for the tz SQLite storage engine.
//!
//! Exports a small C-ABI surface that the host worker calls to run SQLite
//! against the OPFS VFS. Strings cross the boundary as (ptr, len) pairs into
//! wasm linear memory; the JS side allocates with `tzdb_alloc` and frees with
//! `tzdb_free`.
//!
//! The benchmark entry `tzdb_bench` runs the full 1,000-insert + query loop
//! inside wasm so per-call JS↔wasm overhead does not pollute the number.
const std = @import("std");
const c = @import("c.zig").c;
const vfs = @import("vfs_opfs.zig");
const Database = @import("Database.zig").Database;
const Statement = @import("Database.zig").Statement;
const StepResult = @import("Database.zig").StepResult;

// wasm_shim.zig's exported libc symbols must be linked in; importing it for
// side effects is not possible in Zig, so reference a decl to keep it alive.
comptime {
    _ = @import("wasm_shim.zig");
}

const allocator = std.heap.wasm_allocator;

/// Monotonic millisecond clock provided by the host worker.
extern fn js_now_ms() u64;

// --- memory helpers (JS allocates/frees buffers for strings) ---

export fn tzdb_alloc(len: usize) ?[*]u8 {
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

export fn tzdb_free(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}

// --- sqlite3_os_init: SQLITE_OS_OTHER requires the app to provide it.
// sqlite3_initialize() (called automatically by sqlite3_open_v2) invokes this;
// its only job is to register the OPFS VFS. Do NOT call sqlite3_initialize()
// here — that would recurse.

export fn sqlite3_os_init() c_int {
    return vfs.register();
}

export fn sqlite3_os_end() c_int {
    return c.SQLITE_OK;
}

// --- handle table (sqlite3* / sqlite3_stmt* are opaque C pointers; we keep
// them behind stable integer handles so JS never touches raw pointers) ---

var db_slots: [8]?*c.sqlite3 = .{null} ** 8;
var stmt_slots: [32]?*c.sqlite3_stmt = .{null} ** 32;

fn nextDbSlot() ?i32 {
    for (db_slots, 0..) |s, i| {
        if (s == null) return @intCast(i);
    }
    return null;
}

fn nextStmtSlot() ?i32 {
    for (stmt_slots, 0..) |s, i| {
        if (s == null) return @intCast(i);
    }
    return null;
}

/// Open (or create) a database file through the OPFS VFS. Returns a db handle
/// >= 0, or -1 on failure. path_ptr/path_len reference a UTF-8 filename.
export fn tzdb_open(path_ptr: [*]const u8, path_len: usize) i32 {
    const path = allocator.dupeZ(u8, path_ptr[0..path_len]) catch return -1;
    defer allocator.free(path);

    const slot = nextDbSlot() orelse return -1;
    var handle: ?*c.sqlite3 = null;
    // flags: READWRITE | CREATE | FULLMUTEX not needed (THREADSAFE=0)
    const rc = c.sqlite3_open_v2(path.ptr, &handle, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, "opfs");
    if (rc != c.SQLITE_OK) {
        if (handle) |h| _ = c.sqlite3_close(h);
        return -1;
    }
    db_slots[@intCast(slot)] = handle;
    return slot;
}

/// Close a database. Returns 0 on success, nonzero on failure.
export fn tzdb_close(db: i32) i32 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;
    const rc = c.sqlite3_close(h);
    if (rc == c.SQLITE_OK) db_slots[@intCast(db)] = null;
    return rc;
}

/// Run one or more SQL statements that return no rows. Returns 0 on success.
export fn tzdb_exec(db: i32, sql_ptr: [*]const u8, sql_len: usize) i32 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;
    const sql = allocator.dupeZ(u8, sql_ptr[0..sql_len]) catch return -1;
    defer allocator.free(sql);

    var err_msg: [*c]u8 = null;
    defer if (err_msg != null) c.sqlite3_free(err_msg);
    const rc = c.sqlite3_exec(h, sql.ptr, null, null, &err_msg);
    return rc;
}

/// Prepare a statement. Returns a stmt handle >= 0, or -1 on failure.
export fn tzdb_prepare(db: i32, sql_ptr: [*]const u8, sql_len: usize) i32 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;
    const sql = allocator.dupeZ(u8, sql_ptr[0..sql_len]) catch return -1;
    defer allocator.free(sql);

    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(h, sql.ptr, @intCast(sql.len), &stmt, null);
    if (rc != c.SQLITE_OK) return -1;
    const slot = nextStmtSlot() orelse {
        _ = c.sqlite3_finalize(stmt);
        return -1;
    };
    stmt_slots[@intCast(slot)] = stmt;
    return slot;
}

/// Step a statement. Returns 100 (SQLITE_ROW), 101 (SQLITE_DONE), or an error code.
export fn tzdb_step(stmt: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_step(h);
}

/// Reset a statement so it can be re-stepped with new bindings.
export fn tzdb_reset(stmt: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_reset(h);
}

/// Finalize (free) a statement.
export fn tzdb_finalize(stmt: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    const rc = c.sqlite3_finalize(h);
    if (rc == c.SQLITE_OK) stmt_slots[@intCast(stmt)] = null;
    return rc;
}

// --- bindings (1-based index, like SQLite) ---

export fn tzdb_bind_int(stmt: i32, idx: i32, val: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_bind_int(h, idx, val);
}

export fn tzdb_bind_int64(stmt: i32, idx: i32, val: i64) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_bind_int64(h, idx, val);
}

export fn tzdb_bind_text(stmt: i32, idx: i32, val_ptr: [*]const u8, val_len: usize) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_bind_text(h, idx, val_ptr, @intCast(val_len), c.SQLITE_TRANSIENT);
}

export fn tzdb_bind_null(stmt: i32, idx: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_bind_null(h, idx);
}

// --- column access ---

export fn tzdb_column_count(stmt: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_column_count(h);
}

export fn tzdb_column_int(stmt: i32, col: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_column_int(h, col);
}

export fn tzdb_column_int64(stmt: i32, col: i32) i64 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_column_int64(h, col);
}

/// Returns the byte length of the text/blob in column `col`.
export fn tzdb_column_bytes(stmt: i32, col: i32) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    return c.sqlite3_column_bytes(h, col);
}

/// Copies the text/blob value of column `col` into `dst` (up to dst_len).
/// Returns bytes copied, or -1. Use tzdb_column_bytes first to size dst.
export fn tzdb_column_blob(stmt: i32, col: i32, dst: [*]u8, dst_len: usize) i32 {
    if (stmt < 0 or stmt >= stmt_slots.len) return -1;
    const h = stmt_slots[@intCast(stmt)] orelse return -1;
    const src = c.sqlite3_column_blob(h, col);
    if (src == null) return 0;
    const n = c.sqlite3_column_bytes(h, col);
    if (n < 0) return -1;
    const len: usize = @intCast(n);
    const copy = @min(len, dst_len);
    const src_ptr: [*]const u8 = @ptrCast(src);
    @memcpy(dst[0..copy], src_ptr[0..copy]);
    return @intCast(copy);
}

// --- misc ---

/// Returns the last error message of `db`, written into `dst`. Returns length.
export fn tzdb_errmsg(db: i32, dst: [*]u8, dst_len: usize) i32 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;
    const msg = c.sqlite3_errmsg(h);
    if (msg == null) return 0;
    const m = std.mem.span(msg);
    const copy = @min(m.len, dst_len);
    @memcpy(dst[0..copy], m[0..copy]);
    return @intCast(copy);
}

export fn tzdb_changes(db: i32) i64 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;
    return c.sqlite3_changes64(h);
}

// --- benchmark ---
// Runs the POC benchmark inside wasm: create schema, insert N messages in one
// transaction, run COUNT + paged SELECTs. Writes a JSON-ish report into `out`.
// Returns bytes written, or -1.

const BenchResult = struct {
    insert_ms: u64,
    count_ms: u64,
    page_ms: u64,
    rows: i64,
    ok: bool,
    err: [128]u8 = .{0} ** 128,
    err_len: usize = 0,
};

fn nowMs() u64 {
    return js_now_ms();
}

fn recordErr(res2: *BenchResult, h: ?*c.sqlite3) void {
    const hh = h orelse return;
    const msg = c.sqlite3_errmsg(hh);
    if (msg != null) {
        const m = std.mem.span(msg);
        const n = @min(m.len, res2.err.len);
        @memcpy(res2.err[0..n], m[0..n]);
        res2.err_len = n;
    }
}

export fn tzdb_bench(db: i32, n: i32, out: [*]u8, out_len: usize) i32 {
    if (db < 0 or db >= db_slots.len) return -1;
    const h = db_slots[@intCast(db)] orelse return -1;

    // schema (same as src/db/schema.zig, inlined to keep this file self-contained)
    const schema_sql =
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
        \\CREATE INDEX IF NOT EXISTS idx_messages_peer_date ON messages(peer_id, date);
        \\CREATE TABLE IF NOT EXISTS peers (
        \\    id INTEGER PRIMARY KEY,
        \\    access_hash INTEGER NOT NULL,
        \\    type TEXT NOT NULL,
        \\    username TEXT,
        \\    title TEXT,
        \\    updated_at INTEGER NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS dialogs (
        \\    peer_id INTEGER PRIMARY KEY,
        \\    top_message_id INTEGER NOT NULL DEFAULT 0,
        \\    unread_count INTEGER NOT NULL DEFAULT 0,
        \\    draft TEXT,
        \\    updated_at INTEGER NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS kv_meta (
        \\    key TEXT PRIMARY KEY,
        \\    value TEXT NOT NULL
        \\);
    ;
    _ = c.sqlite3_exec(h, schema_sql, null, null, null);

    var res = BenchResult{ .insert_ms = 0, .count_ms = 0, .page_ms = 0, .rows = 0, .ok = false };
    var w: std.Io.Writer = .fixed(out[0..out_len]);

    // --- insert phase ---
    const t0 = nowMs();
    if (c.sqlite3_exec(h, "BEGIN TRANSACTION;", null, null, null) != c.SQLITE_OK) recordErr(&res, h);
    var stmt: ?*c.sqlite3_stmt = null;
    const prep_rc = c.sqlite3_prepare_v2(
        h,
        "INSERT INTO messages (id, peer_id, from_id, date, message, out, flags) VALUES (?,?,?,?,?,?,?);",
        -1,
        &stmt,
        null,
    );
    if (prep_rc != c.SQLITE_OK) recordErr(&res, h);
    var i: i32 = 0;
    while (i < n) : (i += 1) {
        _ = c.sqlite3_bind_int64(stmt, 1, i);
        _ = c.sqlite3_bind_int64(stmt, 2, 123456789);
        _ = c.sqlite3_bind_int64(stmt, 3, 123456789);
        _ = c.sqlite3_bind_int64(stmt, 4, 1700000000 + i);
        _ = c.sqlite3_bind_text(stmt, 5, "Hello Telegram message from Zig SQLite", 38, c.SQLITE_TRANSIENT);
        _ = c.sqlite3_bind_int(stmt, 6, 0);
        _ = c.sqlite3_bind_int(stmt, 7, 0);
        const sr = c.sqlite3_step(stmt);
        if (sr != c.SQLITE_DONE) {
            recordErr(&res, h);
            break;
        }
        _ = c.sqlite3_reset(stmt);
    }
    if (stmt) |s| _ = c.sqlite3_finalize(s);
    if (c.sqlite3_exec(h, "COMMIT;", null, null, null) != c.SQLITE_OK) recordErr(&res, h);
    res.insert_ms = nowMs() - t0;

    // --- count phase ---
    const t1 = nowMs();
    _ = c.sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM messages WHERE peer_id = ?;", -1, &stmt, null);
    _ = c.sqlite3_bind_int64(stmt, 1, 123456789);
    if (c.sqlite3_step(stmt) == c.SQLITE_ROW) res.rows = c.sqlite3_column_int64(stmt, 0);
    _ = c.sqlite3_finalize(stmt);
    res.count_ms = nowMs() - t1;

    // --- paged select phase (10 pages of 100) ---
    const t2 = nowMs();
    _ = c.sqlite3_prepare_v2(h, "SELECT id, message FROM messages WHERE peer_id = ? ORDER BY date DESC LIMIT 100 OFFSET ?;", -1, &stmt, null);
    var page: i32 = 0;
    while (page < 10) : (page += 1) {
        _ = c.sqlite3_bind_int64(stmt, 1, 123456789);
        _ = c.sqlite3_bind_int64(stmt, 2, page * 100);
        while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {}
        _ = c.sqlite3_reset(stmt);
    }
    _ = c.sqlite3_finalize(stmt);
    res.page_ms = nowMs() - t2;

    res.ok = (res.rows == n);

    w.print("{{\"insert_ms\":{d},\"count_ms\":{d},\"page_ms\":{d},\"rows\":{d},\"ok\":{},\"err\":\"{s}\"}}", .{
        res.insert_ms, res.count_ms, res.page_ms, res.rows, res.ok, res.err[0..res.err_len],
    }) catch return -1;
    return @intCast(w.buffered().len);
}

