const Msg = @This();
const std = @import("std");
const types = @import("types");
const functions = @import("functions");
const Context = @import("Context.zig");
const File = @import("File.zig");
const client = @import("client.zig");

/// The concrete message struct (types.Message_ — not the Message union).
pub const Raw = types.Message_;

ctx: Context,
raw: Raw,

/// Register a fn(Msg) !void as a Handler for UpdateNewMessage.
/// Filters non-Message variants (empty/service) silently.
pub fn handler(comptime cb: fn (Msg) anyerror!void) client.Handler {
    return client.handler(types.UpdateNewMessage, struct {
        fn dispatch(ctx: Context, update: types.UpdateNewMessage) anyerror!void {
            const msg = from(ctx, update) orelse return;
            try cb(msg);
        }
    }.dispatch);
}

pub fn from(ctx: Context, update: types.UpdateNewMessage) ?Msg {
    return switch (update.message) {
        .Message => |m| .{ .ctx = ctx, .raw = m },
        else => null,
    };
}

// --- Accessors (no switch — raw is already the concrete struct) ---

pub fn text(self: Msg) []const u8 {
    return self.raw.message;
}

pub fn is(self: Msg, s: []const u8) bool {
    return std.mem.eql(u8, self.raw.message, s);
}

pub fn prefix(self: Msg, s: []const u8) bool {
    return std.mem.startsWith(u8, self.raw.message, s);
}

pub fn contains(self: Msg, s: []const u8) bool {
    return std.mem.indexOf(u8, self.raw.message, s) != null;
}

pub fn id(self: Msg) i32 {
    return self.raw.id;
}

pub fn date(self: Msg) i32 {
    return self.raw.date;
}

pub fn senderId(self: Msg) ?i64 {
    const from_id = self.raw.from_id.value orelse {
        // Private chats omit from_id since layer 119; sender is the peer.
        return if (self.raw.peer_id == .PeerUser) self.raw.peer_id.PeerUser.user_id else null;
    };
    return switch (from_id) {
        .PeerUser => |p| p.user_id,
        else => null,
    };
}

pub fn replyToId(self: Msg) ?i32 {
    const rt = self.raw.reply_to.value orelse return null;
    return switch (rt) {
        .MessageReplyHeader => |rh| rh.reply_to_msg_id.value,
        else => null,
    };
}

pub fn mediaLocation(self: Msg) ?types.InputFileLocation {
    const med = self.raw.media.value orelse return null;
    return switch (med) {
        .MessageMediaPhoto => |mp| File.photoLocation(mp.photo.value orelse return null),
        .MessageMediaDocument => |mdoc| File.documentLocation(mdoc.document.value orelse return null),
        else => null,
    };
}

/// Resolve the peer this message was sent to.
/// Checks entities (current-update cache) first, falls back to session peer_cache.
pub fn peer(self: Msg) ?types.InputPeer {
    return switch (self.raw.peer_id) {
        .PeerUser => |p| blk: {
            const ah = self.ctx.entities.accessHash(p.user_id) orelse break :blk self.ctx.resolvePeer(p.user_id);
            break :blk .{ .InputPeerUser = .{ .user_id = p.user_id, .access_hash = ah } };
        },
        .PeerChat => |p| .{ .InputPeerChat = .{ .chat_id = p.chat_id } },
        .PeerChannel => |p| blk: {
            const ah = self.ctx.entities.channelAccessHash(p.channel_id) orelse break :blk self.ctx.resolvePeer(p.channel_id);
            break :blk .{ .InputPeerChannel = .{ .channel_id = p.channel_id, .access_hash = ah } };
        },
    };
}

// --- Active operations ---

/// Send a plain-text message to the same peer without a reply thread.
pub fn respond(self: Msg, txt: []const u8) !void {
    const p = self.peer() orelse return;
    try self.ctx.exec(functions.messages.SendMessage{ .peer = p, .message = txt });
}

/// Send a plain-text reply that references this message (shows quote in clients).
pub fn reply(self: Msg, txt: []const u8) !void {
    const p = self.peer() orelse return;
    try self.ctx.exec(functions.messages.SendMessage{
        .peer = p,
        .message = txt,
        .reply_to = .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = self.raw.id } }),
    });
}

/// Reply with pre-built formatting entities (e.g. from FormattedText).
pub fn replyFmt(self: Msg, txt: []const u8, entities: []types.MessageEntity) !void {
    const p = self.peer() orelse return;
    try self.ctx.exec(functions.messages.SendMessage{
        .peer = p,
        .message = txt,
        .entities = .some(entities),
        .reply_to = .some(.{ .InputReplyToMessage = .{ .reply_to_msg_id = self.raw.id } }),
    });
}
