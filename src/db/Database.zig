const std = @import("std");
const c = @import("c.zig").c;

pub const Database = struct {
    handle: ?*c.sqlite3 = null,

    pub const Error = error{
        SqliteError,
        SqliteBusy,
        SqliteLocked,
        SqliteConstraint,
        SqliteMismatch,
        SqliteCorrupt,
        SqliteNotFound,
        SqliteFull,
        SqliteCannotOpen,
        SqliteSchema,
        SqliteOutOfMemory,
        StepError,
        BindError,
        PrepareError,
        ExecError,
    };

    pub fn mapError(rc: c_int) Error {
        return switch (rc) {
            c.SQLITE_BUSY => error.SqliteBusy,
            c.SQLITE_LOCKED => error.SqliteLocked,
            c.SQLITE_CONSTRAINT => error.SqliteConstraint,
            c.SQLITE_MISMATCH => error.SqliteMismatch,
            c.SQLITE_CORRUPT => error.SqliteCorrupt,
            c.SQLITE_NOTFOUND => error.SqliteNotFound,
            c.SQLITE_FULL => error.SqliteFull,
            c.SQLITE_CANTOPEN => error.SqliteCannotOpen,
            c.SQLITE_SCHEMA => error.SqliteSchema,
            c.SQLITE_NOMEM => error.SqliteOutOfMemory,
            else => error.SqliteError,
        };
    }

    pub fn open(path: [:0]const u8) Error!Database {
        var db_handle: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path.ptr, &db_handle);
        if (rc != c.SQLITE_OK) {
            if (db_handle) |h| _ = c.sqlite3_close(h);
            return mapError(rc);
        }
        return .{ .handle = db_handle };
    }

    pub fn openVfs(path: [:0]const u8, vfs_name: ?[:0]const u8, flags: c_int) Error!Database {
        var db_handle: ?*c.sqlite3 = null;
        const vfs_ptr = if (vfs_name) |v| v.ptr else null;
        const rc = c.sqlite3_open_v2(path.ptr, &db_handle, flags, vfs_ptr);
        if (rc != c.SQLITE_OK) {
            if (db_handle) |h| _ = c.sqlite3_close(h);
            return mapError(rc);
        }
        return .{ .handle = db_handle };
    }

    pub fn close(self: *Database) void {
        if (self.handle) |h| {
            _ = c.sqlite3_close(h);
            self.handle = null;
        }
    }

    pub fn deinit(self: *Database) void {
        self.close();
    }

    pub fn getErrMsg(self: *const Database) []const u8 {
        if (self.handle) |h| {
            const ptr = c.sqlite3_errmsg(h);
            if (ptr != null) {
                return std.mem.span(ptr);
            }
        }
        return "unknown sqlite error";
    }

    pub fn exec(self: *const Database, sql: [:0]const u8) Error!void {
        const h = self.handle orelse return error.SqliteCannotOpen;
        var err_msg: [*c]u8 = null;
        defer if (err_msg != null) c.sqlite3_free(err_msg);

        const rc = c.sqlite3_exec(h, sql.ptr, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            return mapError(rc);
        }
    }

    pub fn prepare(self: *const Database, sql: [:0]const u8) Error!Statement {
        const h = self.handle orelse return error.SqliteCannotOpen;
        var stmt_handle: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(h, sql.ptr, @intCast(sql.len), &stmt_handle, null);
        if (rc != c.SQLITE_OK) {
            return mapError(rc);
        }
        return .{ .handle = stmt_handle };
    }

    pub fn lastInsertRowId(self: *const Database) i64 {
        const h = self.handle orelse return 0;
        return c.sqlite3_last_insert_rowid(h);
    }

    pub fn changes(self: *const Database) i32 {
        const h = self.handle orelse return 0;
        return c.sqlite3_changes(h);
    }

    pub fn beginTransaction(self: *const Database) Error!void {
        try self.exec("BEGIN TRANSACTION;");
    }

    pub fn commit(self: *const Database) Error!void {
        try self.exec("COMMIT;");
    }

    pub fn rollback(self: *const Database) Error!void {
        try self.exec("ROLLBACK;");
    }
};

pub const StepResult = enum {
    row,
    done,
};

pub const Statement = struct {
    handle: ?*c.sqlite3_stmt = null,

    pub fn finalize(self: *Statement) void {
        if (self.handle) |h| {
            _ = c.sqlite3_finalize(h);
            self.handle = null;
        }
    }

    pub fn deinit(self: *Statement) void {
        self.finalize();
    }

    pub fn reset(self: *const Statement) Database.Error!void {
        const h = self.handle orelse return error.StepError;
        const rc = c.sqlite3_reset(h);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn clearBindings(self: *const Statement) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_clear_bindings(h);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn step(self: *const Statement) Database.Error!StepResult {
        const h = self.handle orelse return error.StepError;
        const rc = c.sqlite3_step(h);
        return switch (rc) {
            c.SQLITE_ROW => .row,
            c.SQLITE_DONE => .done,
            else => Database.mapError(rc),
        };
    }

    pub fn bindInt(self: *const Statement, idx: c_int, val: i32) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_bind_int(h, idx, val);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn bindInt64(self: *const Statement, idx: c_int, val: i64) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_bind_int64(h, idx, val);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn bindText(self: *const Statement, idx: c_int, val: []const u8) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_bind_text(h, idx, val.ptr, @intCast(val.len), c.SQLITE_TRANSIENT);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn bindBlob(self: *const Statement, idx: c_int, val: []const u8) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_bind_blob(h, idx, val.ptr, @intCast(val.len), c.SQLITE_TRANSIENT);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn bindNull(self: *const Statement, idx: c_int) Database.Error!void {
        const h = self.handle orelse return error.BindError;
        const rc = c.sqlite3_bind_null(h, idx);
        if (rc != c.SQLITE_OK) return Database.mapError(rc);
    }

    pub fn columnInt(self: *const Statement, col: c_int) i32 {
        const h = self.handle orelse return 0;
        return c.sqlite3_column_int(h, col);
    }

    pub fn columnInt64(self: *const Statement, col: c_int) i64 {
        const h = self.handle orelse return 0;
        return c.sqlite3_column_int64(h, col);
    }

    pub fn columnText(self: *const Statement, col: c_int) []const u8 {
        const h = self.handle orelse return "";
        const ptr = c.sqlite3_column_text(h, col);
        const bytes = c.sqlite3_column_bytes(h, col);
        if (ptr == null or bytes <= 0) return "";
        return ptr[0..@intCast(bytes)];
    }

    pub fn columnBlob(self: *const Statement, col: c_int) []const u8 {
        const h = self.handle orelse return "";
        const ptr = c.sqlite3_column_blob(h, col);
        const bytes = c.sqlite3_column_bytes(h, col);
        if (ptr == null or bytes <= 0) return "";
        const u8_ptr: [*]const u8 = @ptrCast(ptr);
        return u8_ptr[0..@intCast(bytes)];
    }

    pub fn columnType(self: *const Statement, col: c_int) c_int {
        const h = self.handle orelse return c.SQLITE_NULL;
        return c.sqlite3_column_type(h, col);
    }
};
