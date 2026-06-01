const std = @import("std");
const types = @import("types");
const unions = @import("unions");
const functions = @import("functions");
const client = @import("../Context.zig");
const File = @import("../File.zig");
const Msg = @import("../Msg.zig");

pub const SendMediaOptions = struct {
    caption: []const u8 = "",
    reply_to: ?i32 = null,
};

pub const AudioOptions = struct {
    caption: []const u8 = "",
    reply_to: ?i32 = null,
    duration: i32 = 0,
    title: ?[]const u8 = null,
    performer: ?[]const u8 = null,
    name: []const u8 = "audio",
};

pub const VideoOptions = struct {
    caption: []const u8 = "",
    reply_to: ?i32 = null,
    duration: f64 = 0,
    w: i32 = 0,
    h: i32 = 0,
    supports_streaming: bool = true,
    name: []const u8 = "video",
};

pub const VoiceOptions = struct {
    caption: []const u8 = "",
    reply_to: ?i32 = null,
    duration: i32 = 0,
    name: []const u8 = "voice.ogg",
};

pub const AlbumItemKind = enum { photo, document };

pub const AlbumItem = struct {
    data: []const u8,
    caption: []const u8 = "",
    name: []const u8 = "file",
    kind: AlbumItemKind = .photo,
    mime_type: []const u8 = "application/octet-stream",
};

pub const AlbumOptions = struct {
    reply_to: ?i32 = null,
};

pub fn sendPhoto(msg: Msg, data: []const u8, opts: SendMediaOptions) !void {
    const peer = msg.peer() orelse return;
    const input_file = try File.upload(msg.ctx, data, "photo.jpg");
    defer switch (input_file) {
        .InputFile => |f| msg.ctx.allocator.free(f.md5_checksum),
        .InputFileBig, .InputFileStoryDocument => {},
    };
    try msg.ctx.exec(functions.messages.SendMedia{
        .peer = peer,
        .media = .{ .InputMediaUploadedPhoto = .{ .file = input_file } },
        .message = opts.caption,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}

pub fn sendDocument(msg: Msg, data: []const u8, mime_type: []const u8, opts: SendMediaOptions) !void {
    const peer = msg.peer() orelse return;
    const input_file = try File.upload(msg.ctx, data, "file");
    defer switch (input_file) {
        .InputFile => |f| msg.ctx.allocator.free(f.md5_checksum),
        .InputFileBig, .InputFileStoryDocument => {},
    };
    var attrs = [_]unions.DocumentAttribute{.{ .DocumentAttributeFilename = .{ .file_name = "file" } }};
    try msg.ctx.exec(functions.messages.SendMedia{
        .peer = peer,
        .media = .{ .InputMediaUploadedDocument = .{
            .file = input_file,
            .mime_type = mime_type,
            .attributes = &attrs,
        } },
        .message = opts.caption,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}

pub fn sendAudio(msg: Msg, data: []const u8, mime_type: []const u8, opts: AudioOptions) !void {
    const peer = msg.peer() orelse return;
    const input_file = try File.upload(msg.ctx, data, opts.name);
    defer switch (input_file) {
        .InputFile => |f| msg.ctx.allocator.free(f.md5_checksum),
        .InputFileBig, .InputFileStoryDocument => {},
    };
    var attrs = [_]unions.DocumentAttribute{.{ .DocumentAttributeAudio = .{
        .duration = opts.duration,
        .title = if (opts.title) |t| .some(t) else .none,
        .performer = if (opts.performer) |p| .some(p) else .none,
    } }};
    try msg.ctx.exec(functions.messages.SendMedia{
        .peer = peer,
        .media = .{ .InputMediaUploadedDocument = .{
            .file = input_file,
            .mime_type = mime_type,
            .attributes = &attrs,
        } },
        .message = opts.caption,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}

pub fn sendVideo(msg: Msg, data: []const u8, mime_type: []const u8, opts: VideoOptions) !void {
    const peer = msg.peer() orelse return;
    const input_file = try File.upload(msg.ctx, data, opts.name);
    defer switch (input_file) {
        .InputFile => |f| msg.ctx.allocator.free(f.md5_checksum),
        .InputFileBig, .InputFileStoryDocument => {},
    };
    var attrs = [_]unions.DocumentAttribute{.{ .DocumentAttributeVideo = .{
        .supports_streaming = if (opts.supports_streaming) .some({}) else .none,
        .duration = opts.duration,
        .w = opts.w,
        .h = opts.h,
    } }};
    try msg.ctx.exec(functions.messages.SendMedia{
        .peer = peer,
        .media = .{ .InputMediaUploadedDocument = .{
            .file = input_file,
            .mime_type = mime_type,
            .attributes = &attrs,
        } },
        .message = opts.caption,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}

pub fn sendVoice(msg: Msg, data: []const u8, opts: VoiceOptions) !void {
    const peer = msg.peer() orelse return;
    const input_file = try File.upload(msg.ctx, data, opts.name);
    defer switch (input_file) {
        .InputFile => |f| msg.ctx.allocator.free(f.md5_checksum),
        .InputFileBig, .InputFileStoryDocument => {},
    };
    var attrs = [_]unions.DocumentAttribute{.{ .DocumentAttributeAudio = .{
        .voice = .some({}),
        .duration = opts.duration,
    } }};
    try msg.ctx.exec(functions.messages.SendMedia{
        .peer = peer,
        .media = .{ .InputMediaUploadedDocument = .{
            .file = input_file,
            .mime_type = "audio/ogg",
            .attributes = &attrs,
        } },
        .message = opts.caption,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}

pub fn sendAlbum(msg: Msg, items: []const AlbumItem, opts: AlbumOptions) !void {
    const peer = msg.peer() orelse return;
    const allocator = msg.ctx.allocator;

    const media_items = try allocator.alloc(types.InputSingleMedia, items.len);
    defer allocator.free(media_items);
    const checksums = try allocator.alloc(?[]const u8, items.len);
    defer allocator.free(checksums);
    defer for (checksums) |c| if (c) |s| allocator.free(s);
    @memset(checksums, null);
    const attrs_buf = try allocator.alloc(unions.DocumentAttribute, items.len);
    defer allocator.free(attrs_buf);

    // Each staged response owns the file_reference bytes referenced by media_items,
    // so the responses must outlive the SendMultiMedia call below.
    const Staged = client.Response(functions.messages.UploadMedia.Response);
    const staged_responses = try allocator.alloc(Staged, items.len);
    defer allocator.free(staged_responses);
    var staged_count: usize = 0;
    defer for (staged_responses[0..staged_count]) |s| s.deinit();

    for (items, 0..) |item, i| {
        const input_file = try File.upload(msg.ctx, item.data, item.name);
        if (input_file == .InputFile) checksums[i] = input_file.InputFile.md5_checksum;
        const uploaded: unions.InputMedia = switch (item.kind) {
            .photo => .{ .InputMediaUploadedPhoto = .{ .file = input_file } },
            .document => blk: {
                attrs_buf[i] = .{ .DocumentAttributeFilename = .{ .file_name = item.name } };
                break :blk .{ .InputMediaUploadedDocument = .{
                    .file = input_file,
                    .mime_type = item.mime_type,
                    .attributes = attrs_buf[i .. i + 1],
                } };
            },
        };
        // SendMultiMedia rejects InputMediaUploaded* directly — must stage via
        // uploadMedia first, then reference the server-assigned id.
        staged_responses[staged_count] = try msg.ctx.call(functions.messages.UploadMedia{ .peer = peer, .media = uploaded });
        const staged = staged_responses[staged_count].value;
        staged_count += 1;
        const media: unions.InputMedia = switch (staged) {
            .MessageMediaPhoto => |m| blk: {
                const p = switch (m.photo.value orelse return error.NoPhoto) {
                    .Photo => |p| p,
                    else => return error.NoPhoto,
                };
                break :blk .{ .InputMediaPhoto = .{ .id = .{ .InputPhoto = .{
                    .id = p.id,
                    .access_hash = p.access_hash,
                    .file_reference = p.file_reference,
                } } } };
            },
            .MessageMediaDocument => |m| blk: {
                const d = switch (m.document.value orelse return error.NoDocument) {
                    .Document => |d| d,
                    else => return error.NoDocument,
                };
                break :blk .{ .InputMediaDocument = .{ .id = .{ .InputDocument = .{
                    .id = d.id,
                    .access_hash = d.access_hash,
                    .file_reference = d.file_reference,
                } } } };
            },
            else => return error.UnexpectedMediaType,
        };
        // SAFETY: immediately overwritten by io.random below
        var rand_id: i64 = undefined;
        msg.ctx.io.random(std.mem.asBytes(&rand_id));
        media_items[i] = .{ .media = media, .message = item.caption, .random_id = rand_id };
    }

    try msg.ctx.exec(functions.messages.SendMultiMedia{
        .peer = peer,
        .multi_media = media_items,
        .reply_to = if (opts.reply_to) |id| .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = id } }) else .none,
    });
}
