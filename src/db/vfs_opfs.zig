//! OPFS VFS for SQLite on wasm32-freestanding.
//!
//! With `-DSQLITE_OS_OTHER=1` sqlite does not ship a VFS; the application must
//! register one. This VFS bridges every file operation to JS functions that the
//! host worker implements on top of `FileSystemSyncAccessHandle` (OPFS).
//!
//! The JS side owns a `fd -> SyncAccessHandle` map. sqlite hands us opaque
//! `sqlite3_file` pointers whose first field we control: we store our own
//! `OpfsFile` (io-methods pointer + fd) there.
//!
//! Design notes:
//! - Single connection (SQLITE_THREADSAFE=0), so xLock/xUnlock are no-ops.
//! - WAL is compiled out (SQLITE_OMIT_WAL), so no xShm* methods are required.
//! - xDelete cannot synchronously remove an OPFS entry (remove() is async);
//!   the JS side marks the name deleted and truncates on next open. Good
//!   enough for a feasibility spike; revisit for production.
const std = @import("std");
const c = @import("c.zig").c;

// --- JS imports (implemented by the host worker) ---
// All return -1 on error unless noted.

extern fn js_opfs_open(name: [*]const u8, name_len: usize, create: bool) i32;
extern fn js_opfs_delete(name: [*]const u8, name_len: usize) i32;
extern fn js_opfs_access(name: [*]const u8, name_len: usize) i32; // 1 exists, 0 no
extern fn js_opfs_read(fd: i32, offset: u64, buf: [*]u8, len: usize) i32; // bytes read
extern fn js_opfs_write(fd: i32, offset: u64, buf: [*]const u8, len: usize) i32; // bytes written
extern fn js_opfs_truncate(fd: i32, size: u64) i32;
extern fn js_opfs_size(fd: i32) i64; // -1 on error
extern fn js_opfs_flush(fd: i32) i32;
extern fn js_opfs_close(fd: i32) void;
extern fn js_opfs_random(buf: [*]u8, len: usize) void;

// sqlite3_file layout: [const sqlite3_io_methods*]. We extend it with our fd.
const OpfsFile = extern struct {
    methods: ?*const c.sqlite3_io_methods,
    fd: i32,
};

fn toFile(pFile: ?*c.sqlite3_file) *OpfsFile {
    return @ptrCast(@alignCast(pFile orelse unreachable));
}

fn cstr(z: [*c]const u8) ?[]const u8 {
    if (z == null) return null;
    return std.mem.span(@as([*:0]const u8, @ptrCast(z)));
}

fn xClose(pFile: ?*c.sqlite3_file) callconv(.c) c_int {
    const f = toFile(pFile);
    if (f.fd >= 0) js_opfs_close(f.fd);
    f.fd = -1;
    return c.SQLITE_OK;
}

fn xRead(pFile: ?*c.sqlite3_file, zBuf: ?*anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const f = toFile(pFile);
    const buf: [*]u8 = @ptrCast(zBuf.?);
    const got = js_opfs_read(f.fd, @intCast(iOfst), buf, @intCast(iAmt));
    if (got < 0) return c.SQLITE_IOERR_READ;
    const want: usize = @intCast(iAmt);
    const have: usize = @intCast(got);
    if (have < want) {
        // Short read at EOF: zero the remainder; sqlite interprets the
        // SQLITE_IOERR_SHORT_READ extended code as EOF.
        @memset(buf[have..want], 0);
        return c.SQLITE_IOERR_SHORT_READ;
    }
    return c.SQLITE_OK;
}

fn xWrite(pFile: ?*c.sqlite3_file, zBuf: ?*const anyopaque, iAmt: c_int, iOfst: i64) callconv(.c) c_int {
    const f = toFile(pFile);
    const buf: [*]const u8 = @ptrCast(zBuf.?);
    const wrote = js_opfs_write(f.fd, @intCast(iOfst), buf, @intCast(iAmt));
    if (wrote < 0) return c.SQLITE_IOERR_WRITE;
    if (@as(usize, @intCast(wrote)) != @as(usize, @intCast(iAmt))) return c.SQLITE_IOERR_WRITE;
    return c.SQLITE_OK;
}

fn xTruncate(pFile: ?*c.sqlite3_file, size: i64) callconv(.c) c_int {
    const f = toFile(pFile);
    if (js_opfs_truncate(f.fd, @intCast(size)) != 0) return c.SQLITE_IOERR_TRUNCATE;
    return c.SQLITE_OK;
}

fn xSync(pFile: ?*c.sqlite3_file, _: c_int) callconv(.c) c_int {
    const f = toFile(pFile);
    if (js_opfs_flush(f.fd) != 0) return c.SQLITE_IOERR_FSYNC;
    return c.SQLITE_OK;
}

fn xFileSize(pFile: ?*c.sqlite3_file, pSize: ?*i64) callconv(.c) c_int {
    const f = toFile(pFile);
    const sz = js_opfs_size(f.fd);
    if (sz < 0) return c.SQLITE_IOERR_SEEK;
    pSize.?.* = sz;
    return c.SQLITE_OK;
}

fn xLock(_: ?*c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK; // single connection
}

fn xUnlock(_: ?*c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn xCheckReservedLock(_: ?*c.sqlite3_file, pResOut: ?*c_int) callconv(.c) c_int {
    pResOut.?.* = 0;
    return c.SQLITE_OK;
}

fn xFileControl(_: ?*c.sqlite3_file, _: c_int, _: ?*anyopaque) callconv(.c) c_int {
    return c.SQLITE_NOTFOUND;
}

fn xSectorSize(_: ?*c.sqlite3_file) callconv(.c) c_int {
    return 4096;
}

fn xDeviceCharacteristics(_: ?*c.sqlite3_file) callconv(.c) c_int {
    return 0;
}

fn xShmMap(_: ?*c.sqlite3_file, _: c_int, _: c_int, _: c_int, _: ?*?*volatile anyopaque) callconv(.c) c_int {
    return c.SQLITE_IOERR; // WAL compiled out
}

fn xShmLock(_: ?*c.sqlite3_file, _: c_int, _: c_int, _: c_int) callconv(.c) c_int {
    return c.SQLITE_IOERR;
}

fn xShmBarrier(_: ?*c.sqlite3_file) callconv(.c) void {}

fn xShmUnmap(_: ?*c.sqlite3_file, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn xFetch(_: ?*c.sqlite3_file, _: i64, _: c_int, _: ?*?*anyopaque) callconv(.c) c_int {
    return c.SQLITE_OK; // unsupported -> sqlite falls back to xRead
}

fn xUnfetch(_: ?*c.sqlite3_file, _: i64, _: ?*anyopaque) callconv(.c) c_int {
    return c.SQLITE_OK;
}

const opfs_io_methods = c.sqlite3_io_methods{
    .iVersion = 3,
    .xClose = xClose,
    .xRead = xRead,
    .xWrite = xWrite,
    .xTruncate = xTruncate,
    .xSync = xSync,
    .xFileSize = xFileSize,
    .xLock = xLock,
    .xUnlock = xUnlock,
    .xCheckReservedLock = xCheckReservedLock,
    .xFileControl = xFileControl,
    .xSectorSize = xSectorSize,
    .xDeviceCharacteristics = xDeviceCharacteristics,
    .xShmMap = xShmMap,
    .xShmLock = xShmLock,
    .xShmBarrier = xShmBarrier,
    .xShmUnmap = xShmUnmap,
    .xFetch = xFetch,
    .xUnfetch = xUnfetch,
};

// --- VFS level ---

fn xOpen(
    vfs: ?*c.sqlite3_vfs,
    zName: [*c]const u8,
    pFile: ?*c.sqlite3_file,
    flags: c_int,
    pOutFlags: [*c]c_int,
) callconv(.c) c_int {
    _ = vfs;
    const f: *OpfsFile = @ptrCast(@alignCast(pFile.?));
    f.methods = &opfs_io_methods;
    f.fd = -1;

    const create = (flags & c.SQLITE_OPEN_CREATE) != 0;
    const name: []const u8 = cstr(zName) orelse "";

    // ":memory:" is handled by sqlite itself and never reaches xOpen.
    const fd = js_opfs_open(name.ptr, name.len, create);
    if (fd < 0) return c.SQLITE_CANTOPEN;
    f.fd = fd;
    if (pOutFlags != null) pOutFlags[0] = flags & (c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_READWRITE);
    return c.SQLITE_OK;
}

fn xDelete(_: ?*c.sqlite3_vfs, zName: [*c]const u8, _: c_int) callconv(.c) c_int {
    const name = cstr(zName) orelse return c.SQLITE_IOERR_DELETE;
    if (js_opfs_delete(name.ptr, name.len) != 0) return c.SQLITE_IOERR_DELETE;
    return c.SQLITE_OK;
}

fn xAccess(_: ?*c.sqlite3_vfs, zName: [*c]const u8, _: c_int, pResOut: [*c]c_int) callconv(.c) c_int {
    const name = cstr(zName) orelse return c.SQLITE_IOERR_ACCESS;
    const exists = js_opfs_access(name.ptr, name.len);
    pResOut[0] = if (exists > 0) 1 else 0;
    return c.SQLITE_OK;
}

fn xFullPathname(_: ?*c.sqlite3_vfs, zName: [*c]const u8, nOut: c_int, zOut: [*c]u8) callconv(.c) c_int {
    // OPFS names are already relative to the origin root; just copy.
    const name = cstr(zName) orelse return c.SQLITE_CANTOPEN;
    if (name.len + 1 > @as(usize, @intCast(nOut))) return c.SQLITE_CANTOPEN;
    @memcpy(zOut[0..name.len], name);
    zOut[name.len] = 0;
    return c.SQLITE_OK;
}

fn xRandomness(_: ?*c.sqlite3_vfs, nByte: c_int, zOut: [*c]u8) callconv(.c) c_int {
    js_opfs_random(@ptrCast(zOut), @intCast(nByte));
    return nByte;
}

fn xSleep(_: ?*c.sqlite3_vfs, _: c_int) callconv(.c) c_int {
    return c.SQLITE_OK;
}

fn xCurrentTime(_: ?*c.sqlite3_vfs, pOut: ?*f64) callconv(.c) c_int {
    // Julian day number. sqlite only uses this for CURRENT_TIME etc.; fixed
    // value is fine for the spike.
    pOut.?.* = 2460000.0;
    return c.SQLITE_OK;
}

fn xGetLastError(_: ?*c.sqlite3_vfs, _: c_int, _: [*c]u8) callconv(.c) c_int {
    return 0;
}

fn xCurrentTimeInt64(_: ?*c.sqlite3_vfs, pOut: ?*i64) callconv(.c) c_int {
    pOut.?.* = 0; // ms since epoch; fixed for the spike
    return c.SQLITE_OK;
}

var opfs_vfs = c.sqlite3_vfs{
    .iVersion = 3,
    .szOsFile = @sizeOf(OpfsFile),
    .mxPathname = 512,
    .pNext = null,
    .zName = "opfs",
    .pAppData = null,
    .xOpen = xOpen,
    .xDelete = xDelete,
    .xAccess = xAccess,
    .xFullPathname = xFullPathname,
    .xDlOpen = null,
    .xDlError = null,
    .xDlSym = null,
    .xDlClose = null,
    .xRandomness = xRandomness,
    .xSleep = xSleep,
    .xCurrentTime = xCurrentTime,
    .xGetLastError = xGetLastError,
    .xCurrentTimeInt64 = xCurrentTimeInt64,
    .xSetSystemCall = null,
    .xGetSystemCall = null,
    .xNextSystemCall = null,
};

/// Registers the OPFS VFS as the default VFS. Called from sqlite3_os_init.
pub fn register() c_int {
    return c.sqlite3_vfs_register(&opfs_vfs, 1);
}
