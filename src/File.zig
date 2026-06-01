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

/// Upload bytes to Telegram. Returns an InputFile ready for use in SendMedia.
/// For small files (≤10 MB) the InputFile.md5_checksum is heap-allocated via
/// ctx.allocator; the caller must free it.
pub fn upload(ctx: Context, data: []const u8, name: []const u8) !unions.InputFile {
    const file_id = codec.nextRandomId();
    const n_parts: i32 = @intCast((data.len + upload_part - 1) / upload_part);
    const is_big = data.len > big_threshold;

    for (0..@intCast(n_parts)) |i| {
        const start = i * upload_part;
        const end = @min(start + upload_part, data.len);
        if (is_big) {
            try ctx.execFile(functions.upload.SaveBigFilePart{
                .file_id = file_id,
                .file_part = @intCast(i),
                .file_total_parts = n_parts,
                .bytes = data[start..end],
            });
        } else {
            try ctx.execFile(functions.upload.SaveFilePart{
                .file_id = file_id,
                .file_part = @intCast(i),
                .bytes = data[start..end],
            });
        }
    }

    if (is_big) {
        return .{ .InputFileBig = .{ .id = file_id, .parts = n_parts, .name = name } };
    }

    var digest: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &digest, .{});
    const md5 = try std.fmt.allocPrint(ctx.allocator, "{s}", .{std.fmt.bytesToHex(&digest, .lower)});
    return .{ .InputFile = .{ .id = file_id, .parts = n_parts, .name = name, .md5_checksum = md5 } };
}
