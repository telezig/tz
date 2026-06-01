const std = @import("std");
const types = @import("types");
const functions = @import("functions");

pub const Context = @import("Context.zig");
pub const Msg = @import("Msg.zig");

pub const media = @import("helpers/media.zig");
pub const keyboard = @import("helpers/keyboard.zig");
pub const FormattedText = @import("helpers/FormattedText.zig");

pub const File = @import("File.zig");
pub const upload = File.upload;
pub const documentLocation = File.documentLocation;
pub const photoLocation = File.photoLocation;

/// Download an entire file into a heap-allocated buffer. caller frees with ctx.allocator.
pub fn download(ctx: Context, location: types.InputFileLocation) ![]u8 {
    var f = File.init(ctx, location);
    defer f.deinit();
    return f.readAll(ctx.allocator);
}

pub const PinOptions = struct {
    silent: bool = false,
    unpin: bool = false,
    pm_oneside: bool = false,
};

pub const EditOptions = struct {
    text: ?[]const u8 = null,
    reply_markup: ?types.ReplyMarkup = null,
};

pub const CallbackAnswerOptions = struct {
    text: ?[]const u8 = null,
    alert: bool = false,
    url: ?[]const u8 = null,
    cache_time: i32 = 0,
};

pub const InlineQueryOptions = struct {
    cache_time: i32 = 300,
    is_gallery: bool = false,
    is_private: bool = false,
    next_offset: ?[]const u8 = null,
};

/// Forward messages by id from one peer to another.
pub fn forwardMessages(ctx: Context, from_peer: types.InputPeer, to_peer: types.InputPeer, ids: []i32) !void {
    const random_ids = try ctx.allocator.alloc(i64, ids.len);
    defer ctx.allocator.free(random_ids);
    for (random_ids) |*r| ctx.io.random(std.mem.asBytes(r));
    try ctx.exec(functions.messages.ForwardMessages{
        .from_peer = from_peer,
        .id = ids,
        .random_id = random_ids,
        .to_peer = to_peer,
    });
}

/// Pin or unpin a message. set opts.unpin to unpin.
pub fn pinMessage(ctx: Context, peer: types.InputPeer, msg_id: i32, opts: PinOptions) !void {
    try ctx.exec(functions.messages.UpdatePinnedMessage{
        .peer = peer,
        .id = msg_id,
        .silent = if (opts.silent) .some({}) else .none,
        .unpin = if (opts.unpin) .some({}) else .none,
        .pm_oneside = if (opts.pm_oneside) .some({}) else .none,
    });
}

/// Edit text and/or reply markup of a message.
pub fn editMessage(ctx: Context, peer: types.InputPeer, msg_id: i32, opts: EditOptions) !void {
    try ctx.exec(functions.messages.EditMessage{
        .peer = peer,
        .id = msg_id,
        .message = if (opts.text) |t| .some(t) else .none,
        .reply_markup = if (opts.reply_markup) |m| .some(m) else .none,
    });
}

/// Delete a message. revokes for all participants where possible.
pub fn deleteMessage(ctx: Context, peer: types.InputPeer, msg_id: i32) !void {
    var ids = [_]i32{msg_id};
    switch (peer) {
        .InputPeerChannel => |p| {
            const chan = types.InputChannel{ .InputChannel = .{
                .channel_id = p.channel_id,
                .access_hash = p.access_hash,
            } };
            try ctx.exec(functions.channels.DeleteMessages{ .channel = chan, .id = &ids });
        },
        else => try ctx.exec(functions.messages.DeleteMessages{
            .revoke = .some({}),
            .id = &ids,
        }),
    }
}

/// Show a typing indicator or other chat action.
pub fn sendChatAction(ctx: Context, peer: types.InputPeer, action: types.SendMessageAction) !void {
    try ctx.exec(functions.messages.SetTyping{ .peer = peer, .action = action });
}

/// Fetch the bot/user's own account info.
pub fn getMe(ctx: Context) !Context.Response([]const types.User) {
    var id = [_]types.InputUser{.{ .InputUserSelf = .{} }};
    const resp = try ctx.call(functions.users.GetUsers{ .id = &id });
    return .{ .arena = resp.arena, .value = resp.value };
}

/// Answer an inline button callback query.
pub fn answerCallbackQuery(ctx: Context, update: types.UpdateBotCallbackQuery, opts: CallbackAnswerOptions) !void {
    try ctx.exec(functions.messages.SetBotCallbackAnswer{
        .alert = if (opts.alert) .some({}) else .none,
        .query_id = update.query_id,
        .message = if (opts.text) |t| .some(t) else .none,
        .url = if (opts.url) |u| .some(u) else .none,
        .cache_time = opts.cache_time,
    });
}

/// Answer a callback query from an inline message button.
pub fn answerInlineCallbackQuery(ctx: Context, update: types.UpdateInlineBotCallbackQuery, opts: CallbackAnswerOptions) !void {
    try ctx.exec(functions.messages.SetBotCallbackAnswer{
        .alert = if (opts.alert) .some({}) else .none,
        .query_id = update.query_id,
        .message = if (opts.text) |t| .some(t) else .none,
        .url = if (opts.url) |u| .some(u) else .none,
        .cache_time = opts.cache_time,
    });
}

/// Answer an inline query with a list of results.
pub fn answerInlineQuery(ctx: Context, update: types.UpdateBotInlineQuery, results: []const types.InputBotInlineResult, opts: InlineQueryOptions) !void {
    try ctx.exec(functions.messages.SetInlineBotResults{
        .gallery = if (opts.is_gallery) .some({}) else .none,
        .private = if (opts.is_private) .some({}) else .none,
        .query_id = update.query_id,
        .results = results,
        .cache_time = opts.cache_time,
        .next_offset = if (opts.next_offset) |o| .some(o) else .none,
    });
}

/// Add an emoji reaction to a message.
pub fn addReaction(ctx: Context, peer: types.InputPeer, msg_id: i32, emoticon: []const u8) !void {
    var reactions = [_]types.Reaction{.{ .ReactionEmoji = .{ .emoticon = emoticon } }};
    try ctx.exec(functions.messages.SendReaction{
        .peer = peer,
        .msg_id = msg_id,
        .reaction = .some(&reactions),
    });
}

/// Remove all reactions from a message.
pub fn removeReaction(ctx: Context, peer: types.InputPeer, msg_id: i32) !void {
    var reactions = [_]types.Reaction{};
    try ctx.exec(functions.messages.SendReaction{
        .peer = peer,
        .msg_id = msg_id,
        .reaction = .some(&reactions),
    });
}

/// Extract the message id from a SendMessage/SendMedia response. null for unexpected shapes.
pub fn sentMessageId(updates: types.Updates) ?i32 {
    return switch (updates) {
        .Updates => |u| blk: {
            for (u.updates) |upd| {
                if (upd == .UpdateMessageID) break :blk upd.UpdateMessageID.id;
            }
            break :blk null;
        },
        .UpdateShortSentMessage => |u| u.id,
        else => null,
    };
}

/// Fetch full user objects for the given ids.
pub fn getUsers(ctx: Context, ids: []const types.InputUser) !Context.Response([]const types.User) {
    const resp = try ctx.call(functions.users.GetUsers{ .id = ids });
    return .{ .arena = resp.arena, .value = resp.value };
}

/// Fetch full chat objects for the given ids.
pub fn getChats(ctx: Context, ids: []const i64) !Context.Response([]const types.Chat) {
    const resp = try ctx.call(functions.messages.GetChats{ .id = ids });
    const chats = switch (resp.value) {
        .MessagesChats => |r| r.chats,
        .MessagesChatsSlice => |r| r.chats,
    };
    return .{ .arena = resp.arena, .value = chats };
}

/// Fetch full channel objects for the given ids.
pub fn getChannels(ctx: Context, ids: []const types.InputChannel) !Context.Response([]const types.Chat) {
    const resp = try ctx.call(functions.channels.GetChannels{ .id = ids });
    const chats = switch (resp.value) {
        .MessagesChats => |r| r.chats,
        .MessagesChatsSlice => |r| r.chats,
    };
    return .{ .arena = resp.arena, .value = chats };
}

/// Resolve the peer from a callback query's peer field using the update's entity cache.
pub fn peerFromCallbackQuery(entities: Context.Entities, update: types.UpdateBotCallbackQuery) ?types.InputPeer {
    return switch (update.peer) {
        .PeerUser => |p| .{ .InputPeerUser = .{
            .user_id = p.user_id,
            .access_hash = entities.accessHash(p.user_id) orelse return null,
        } },
        .PeerChat => |p| .{ .InputPeerChat = .{ .chat_id = p.chat_id } },
        .PeerChannel => |p| .{ .InputPeerChannel = .{
            .channel_id = p.channel_id,
            .access_hash = entities.channelAccessHash(p.channel_id) orelse return null,
        } },
    };
}
