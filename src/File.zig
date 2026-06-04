const File = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const unions = @import("unions");
const functions = @import("functions");
const Context = @import("Context.zig");
const codec = @import("codec");
const aes_ctr = @import("crypto/aes_ctr.zig");
const sha = @import("crypto/sha.zig");

const chunk_size: i32 = 512 * 1024;
const cdn_block: i64 = 128 * 1024;

const CdnState = struct {
    dc_id: i32,
    file_token: []u8, // owned via ctx.allocator
    key: [32]u8,
    iv: [16]u8,
};

ctx: Context,
location: unions.InputFileLocation,
offset: i64 = 0,
done: bool = false,
cdn: ?CdnState = null,
chunk: []u8 = &.{}, // current chunk; owned via ctx.allocator; valid until next next()/deinit()

pub fn init(ctx: Context, location: unions.InputFileLocation) File {
    return .{ .ctx = ctx, .location = location };
}

pub fn deinit(self: *File) void {
    if (self.chunk.len > 0) self.ctx.allocator.free(self.chunk);
    if (self.cdn) |*c| self.ctx.allocator.free(c.file_token);
}

/// Returns the next chunk. The slice is valid until the next call to next() or deinit().
/// Returns null when the download is complete.
pub fn next(self: *File) !?[]const u8 {
    if (self.done) return null;

    if (self.chunk.len > 0) {
        self.ctx.allocator.free(self.chunk);
        self.chunk = &.{};
    }

    if (self.cdn) |cdn| return self.nextCdn(cdn);

    const result = try self.ctx.callFile(functions.upload.GetFile{
        .location = self.location,
        .offset = self.offset,
        .limit = chunk_size,
    });
    defer result.deinit();

    switch (result.value) {
        .UploadFile => |f| {
            if (f.bytes.len == 0) {
                self.done = true;
                return null;
            }
            self.chunk = try self.ctx.allocator.dupe(u8, f.bytes);
            if (f.bytes.len < @as(usize, @intCast(chunk_size))) self.done = true;
            self.offset += @intCast(f.bytes.len);
            return self.chunk;
        },
        .UploadFileCdnRedirect => |r| {
            if (r.encryption_key.len < 32 or r.encryption_iv.len < 16)
                return error.CdnBadKey;
            self.cdn = .{
                .dc_id = r.dc_id,
                .file_token = try self.ctx.allocator.dupe(u8, r.file_token),
                .key = r.encryption_key[0..32].*,
                .iv = r.encryption_iv[0..16].*,
            };
            return self.next();
        },
    }
}

fn nextCdn(self: *File, cdn: CdnState) !?[]const u8 {
    while (true) {
        const result = try self.ctx.callCdn(cdn.dc_id, functions.upload.GetCdnFile{
            .file_token = cdn.file_token,
            .offset = self.offset,
            .limit = chunk_size,
        });
        defer result.deinit();

        switch (result.value) {
            .UploadCdnFile => |f| {
                if (f.bytes.len == 0) {
                    self.done = true;
                    return null;
                }
                const data = try self.ctx.allocator.dupe(u8, f.bytes);
                errdefer self.ctx.allocator.free(data);

                aes_ctr.decrypt(cdn.key, cdn.iv, data, @intCast(self.offset));
                try self.verifyCdnChunk(cdn.file_token, data, self.offset);

                if (f.bytes.len < @as(usize, @intCast(chunk_size))) self.done = true;
                self.offset += @intCast(f.bytes.len);
                self.chunk = data;
                return data;
            },
            .UploadCdnFileReuploadNeeded => |r| {
                const resp = try self.ctx.callFile(functions.upload.ReuploadCdnFile{
                    .file_token = cdn.file_token,
                    .request_token = r.request_token,
                });
                resp.deinit();
                // retry GetCdnFile
            },
        }
    }
}

fn verifyCdnChunk(self: *File, file_token: []const u8, data: []u8, base_offset: i64) !void {
    const hashes_resp = try self.ctx.callFile(functions.upload.GetCdnFileHashes{
        .file_token = file_token,
        .offset = base_offset,
    });
    defer hashes_resp.deinit();
    const hashes = hashes_resp.value;

    var pos: usize = 0;
    while (pos < data.len) {
        const block_off = base_offset + @as(i64, @intCast(pos));
        const block_len: usize = @intCast(@min(cdn_block, @as(i64, @intCast(data.len - pos))));
        const block = data[pos .. pos + block_len];

        var expected: ?[]const u8 = null;
        for (hashes) |h| {
            if (h.offset == block_off) {
                expected = h.hash;
                break;
            }
        }
        if (expected == null) return error.CdnHashMissing;
        const actual = sha.sha256(block);
        if (!std.mem.eql(u8, expected.?, &actual)) return error.CdnHashMismatch;

        pos += block_len;
    }
}

/// Download all bytes. The caller owns the returned slice and must free it with `allocator`.
pub fn readAll(self: *File, allocator: Allocator) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    while (try self.next()) |chunk| {
        try buf.appendSlice(allocator, chunk);
    }
    return buf.toOwnedSlice(allocator);
}

// --- Parallel download ---
//
// Telegram's MTProto connection multiplexes requests (responses are matched by
// msg_id), so several `upload.GetFile` calls can be in flight at once over the
// *same* connection. We exploit that with N worker coroutines that pull part
// indices off a shared atomic counter — the grammers model, no connection pool.
//
// Parallelism needs the total size up front: workers must know which parts exist
// without racing past an unknown EOF. When the size is unknown (size == 0),
// parallelism is disabled, or we are on the CDN path, we fall back to sequential
// `next()`.

const max_workers_cap: usize = 16;

const Dest = union(enum) {
    /// Write each part at `part_index * chunk_size` into one big buffer.
    contiguous: []u8,
    /// Write parts into per-worker scratch slots (streaming, one round at a time).
    slots: struct { base: usize, bufs: [][]u8, lens: []usize },
};

const DownloadJob = struct {
    ctx: Context,
    location: unions.InputFileLocation,
    size: usize,
    /// Next part index to claim. Exclusive upper bound is `limit_part`.
    next_part: std.atomic.Value(usize),
    limit_part: usize,
    dest: Dest,
};

fn downloadWorker(job: *DownloadJob) anyerror!void {
    const part: usize = @intCast(chunk_size);
    while (true) {
        const idx = job.next_part.fetchAdd(1, .monotonic);
        if (idx >= job.limit_part) return;
        const offset = idx * part;
        if (offset >= job.size) return;
        const want: usize = @min(part, job.size - offset);

        const result = try job.ctx.callFile(functions.upload.GetFile{
            .location = job.location,
            .offset = @intCast(offset),
            .limit = chunk_size,
        });
        defer result.deinit();
        switch (result.value) {
            .UploadFile => |f| {
                if (f.bytes.len < want) return error.FileTruncated;
                switch (job.dest) {
                    .contiguous => |buf| @memcpy(buf[offset .. offset + want], f.bytes[0..want]),
                    .slots => |s| {
                        const i = idx - s.base;
                        @memcpy(s.bufs[i][0..want], f.bytes[0..want]);
                        s.lens[i] = want;
                    },
                }
            },
            // The probe already detected/handled CDN; a redirect here would mean
            // the server changed its mind mid-file, which it does not do.
            .UploadFileCdnRedirect => return error.CdnRedirectMidStream,
        }
    }
}

/// Spawn `count` (clamped to [1, max_workers_cap]) worker coroutines, run them to
/// completion, and return the first error any of them produced.
fn spawnWorkers(io: std.Io, comptime workerFn: anytype, job: anytype, count: usize) !void {
    const n = std.math.clamp(count, 1, max_workers_cap);
    const Future = @TypeOf(std.Io.async(io, workerFn, .{job}));
    var futures: [max_workers_cap]Future = undefined;
    for (futures[0..n]) |*f| f.* = std.Io.async(io, workerFn, .{job});
    var first_err: ?anyerror = null;
    for (futures[0..n]) |*f| f.await(io) catch |e| {
        if (first_err == null) first_err = e;
    };
    if (first_err) |e| return e;
}

const Probe = union(enum) {
    cdn, // self.cdn is now set; caller should use the sequential CDN path
    single: []u8, // whole file fit in the first part; slice owned by `allocator`
    multi: []u8, // first part fetched; more parts remain; slice owned by `allocator`
};

/// Fetch part 0 to distinguish a normal file from a CDN redirect before committing
/// to the parallel path. Telegram issues the redirect from offset 0, so after this
/// the parallel workers only ever see normal `UploadFile` responses.
fn probe(self: *File, allocator: Allocator, size: usize) !Probe {
    const first = try self.ctx.callFile(functions.upload.GetFile{
        .location = self.location,
        .offset = 0,
        .limit = chunk_size,
    });
    defer first.deinit();
    switch (first.value) {
        .UploadFileCdnRedirect => |r| {
            if (r.encryption_key.len < 32 or r.encryption_iv.len < 16) return error.CdnBadKey;
            self.cdn = .{
                .dc_id = r.dc_id,
                .file_token = try self.ctx.allocator.dupe(u8, r.file_token),
                .key = r.encryption_key[0..32].*,
                .iv = r.encryption_iv[0..16].*,
            };
            self.offset = 0;
            return .cdn;
        },
        .UploadFile => |f| {
            const part: usize = @intCast(chunk_size);
            const dup = try allocator.dupe(u8, f.bytes);
            if (f.bytes.len < part or size <= part) return .{ .single = dup };
            return .{ .multi = dup };
        },
    }
}

/// Download all bytes, fetching parts in parallel when `size` (the known total, e.g.
/// from `Document.size`) is non-zero and `ctx.file_workers > 1`. Falls back to the
/// sequential `readAll` otherwise, or on CDN files. Caller owns the returned slice.
pub fn downloadAll(self: *File, allocator: Allocator, size: usize) ![]u8 {
    if (self.ctx.file_workers <= 1 or size == 0 or self.cdn != null)
        return self.readAll(allocator);

    switch (try self.probe(allocator, size)) {
        .cdn => return self.readAll(allocator),
        // Trust the server's length: a short first part means the file is just this.
        .single => |first| return first,
        .multi => |first| {
            errdefer allocator.free(first);
            const part: usize = @intCast(chunk_size);
            const total = (size + part - 1) / part;

            const buf = try allocator.alloc(u8, size);
            errdefer allocator.free(buf);
            @memcpy(buf[0..first.len], first);
            allocator.free(first);

            var job = DownloadJob{
                .ctx = self.ctx,
                .location = self.location,
                .size = size,
                .next_part = std.atomic.Value(usize).init(1),
                .limit_part = total,
                .dest = .{ .contiguous = buf },
            };
            try spawnWorkers(self.ctx.io, downloadWorker, &job, self.ctx.file_workers);
            return buf;
        },
    }
}

/// Stream all bytes to `writer`, fetching parts in parallel in rounds of
/// `ctx.file_workers` so peak memory stays bounded (workers × chunk_size) rather
/// than the whole file. Falls back to sequential streaming when `size` is unknown,
/// parallelism is disabled, or the file is served via CDN.
pub fn downloadTo(self: *File, writer: *std.Io.Writer, size: usize) !void {
    const alloc = self.ctx.allocator;
    if (self.ctx.file_workers <= 1 or size == 0 or self.cdn != null) {
        while (try self.next()) |chunk| try writer.writeAll(chunk);
        return;
    }

    switch (try self.probe(alloc, size)) {
        .cdn => {
            while (try self.next()) |chunk| try writer.writeAll(chunk);
            return;
        },
        .single => |first| {
            defer alloc.free(first);
            try writer.writeAll(first);
            return;
        },
        .multi => |first| {
            {
                defer alloc.free(first);
                try writer.writeAll(first);
            }
            const part: usize = @intCast(chunk_size);
            const total = (size + part - 1) / part;
            const n = std.math.clamp(self.ctx.file_workers, 1, max_workers_cap);

            var bufs: [max_workers_cap][]u8 = undefined;
            var allocated: usize = 0;
            // Single defer keyed on `allocated`: frees exactly the buffers that were
            // successfully allocated, on both the happy path and any later error.
            defer for (bufs[0..allocated]) |b| alloc.free(b);
            while (allocated < n) : (allocated += 1) bufs[allocated] = try alloc.alloc(u8, part);

            var lens: [max_workers_cap]usize = undefined;
            var base: usize = 1; // part 0 already written
            while (base < total) {
                const this_round = @min(n, total - base);
                var job = DownloadJob{
                    .ctx = self.ctx,
                    .location = self.location,
                    .size = size,
                    .next_part = std.atomic.Value(usize).init(base),
                    .limit_part = base + this_round,
                    .dest = .{ .slots = .{ .base = base, .bufs = bufs[0..this_round], .lens = lens[0..this_round] } },
                };
                try spawnWorkers(self.ctx.io, downloadWorker, &job, this_round);
                for (0..this_round) |i| try writer.writeAll(bufs[i][0..lens[i]]);
                base += this_round;
            }
        },
    }
}

// --- Static helpers ---

/// Extract InputFileLocation from a Document.
pub fn documentLocation(doc: unions.Document) ?unions.InputFileLocation {
    const d = switch (doc) {
        .Document => |d| d,
        else => return null,
    };
    return .{ .InputDocumentFileLocation = .{
        .id = d.id,
        .access_hash = d.access_hash,
        .file_reference = d.file_reference,
        .thumb_size = "",
    } };
}

/// Total byte size of a Document, for passing to `downloadAll`/`downloadTo` to
/// enable parallel download. null for non-`Document` variants.
pub fn documentSize(doc: unions.Document) ?usize {
    return switch (doc) {
        .Document => |d| @intCast(d.size),
        else => null,
    };
}

/// Extract InputFileLocation from a Photo, selecting the largest available size.
pub fn photoLocation(photo: unions.Photo) ?unions.InputFileLocation {
    const p = switch (photo) {
        .Photo => |p| p,
        else => return null,
    };
    var best_type: ?[]const u8 = null;
    var best_size: i32 = -1;
    for (p.sizes) |ps| {
        switch (ps) {
            .PhotoSize => |s| if (s.size > best_size) {
                best_size = s.size;
                best_type = s.type;
            },
            .PhotoSizeProgressive => |s| {
                const last = if (s.sizes.len > 0) s.sizes[s.sizes.len - 1] else continue;
                if (last > best_size) {
                    best_size = last;
                    best_type = s.type;
                }
            },
            else => {},
        }
    }
    const size_type = best_type orelse return null;
    return .{ .InputPhotoFileLocation = .{
        .id = p.id,
        .access_hash = p.access_hash,
        .file_reference = p.file_reference,
        .thumb_size = size_type,
    } };
}

// --- Upload ---

const big_threshold = 10 * 1024 * 1024;
const upload_part = 128 * 1024;

const UploadJob = struct {
    ctx: Context,
    data: []const u8,
    file_id: i64,
    n_parts: i32,
    is_big: bool,
    next_part: std.atomic.Value(usize),
};

fn uploadWorker(job: *UploadJob) anyerror!void {
    const total: usize = @intCast(job.n_parts);
    while (true) {
        const i = job.next_part.fetchAdd(1, .monotonic);
        if (i >= total) return;
        const start = i * upload_part;
        const end = @min(start + upload_part, job.data.len);
        if (job.is_big) {
            try job.ctx.execFile(functions.upload.SaveBigFilePart{
                .file_id = job.file_id,
                .file_part = @intCast(i),
                .file_total_parts = job.n_parts,
                .bytes = job.data[start..end],
            });
        } else {
            try job.ctx.execFile(functions.upload.SaveFilePart{
                .file_id = job.file_id,
                .file_part = @intCast(i),
                .bytes = job.data[start..end],
            });
        }
    }
}

/// Upload bytes to Telegram. Returns an InputFile ready for use in SendMedia.
/// Parts are uploaded in parallel (up to ctx.file_workers), multiplexed over the
/// same connection. For small files (≤10 MB) the InputFile.md5_checksum is
/// heap-allocated via ctx.allocator; the caller must free it. The md5 is computed
/// over the whole buffer up front, independent of the part uploads.
pub fn upload(ctx: Context, data: []const u8, name: []const u8) !unions.InputFile {
    const file_id = codec.nextRandomId();
    const n_parts: i32 = @intCast((data.len + upload_part - 1) / upload_part);
    const is_big = data.len > big_threshold;

    var job = UploadJob{
        .ctx = ctx,
        .data = data,
        .file_id = file_id,
        .n_parts = n_parts,
        .is_big = is_big,
        .next_part = std.atomic.Value(usize).init(0),
    };
    try spawnWorkers(ctx.io, uploadWorker, &job, ctx.file_workers);

    if (is_big) {
        return .{ .InputFileBig = .{ .id = file_id, .parts = n_parts, .name = name } };
    }

    var digest: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &digest, .{});
    const md5 = try std.fmt.allocPrint(ctx.allocator, "{s}", .{std.fmt.bytesToHex(&digest, .lower)});
    return .{ .InputFile = .{ .id = file_id, .parts = n_parts, .name = name, .md5_checksum = md5 } };
}
