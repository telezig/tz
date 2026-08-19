//! bot_store — end-to-end message persistence demo.
//!
//! Every incoming message is persisted to a SQLite store (via Store.Sqlite)
//! through the client's `store` option. `/history` queries the last N stored
//! messages for that chat and replies with them — proving the full loop:
//!   Telegram server -> UpdateNewMessage -> PTS-confirmed order
//!     -> Store.Sqlite upsert -> /history -> queryMessages -> reply
//!
//! usage:
//!   TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> zig build bot-store
//!   (api_id/api_hash are required even for bots; the values pre-filled in
//!    web/index.html work: 611335 / d524b414d21f4d37f08684c1df41ac9c)

const std = @import("std");
const tz = @import("tz");
const db = @import("tz_db");

const history_cmd = "/history";

fn peerIdOf(peer: tz.unions.Peer) ?i64 {
    return switch (peer) {
        .PeerUser => |p| p.user_id,
        .PeerChat => |p| p.chat_id,
        .PeerChannel => |p| p.channel_id,
    };
}

fn onMessage(msg: tz.Msg) !void {
    const ctx = msg.ctx;
    const store = ctx.store orelse return;
    const text = msg.text();
    const peer_id = peerIdOf(msg.raw.peer_id) orelse return;

    // Commands are answered from the store (persistence proof), not from msg.
    if (std.mem.startsWith(u8, text, history_cmd)) {
        const n = if (text.len > history_cmd.len)
            std.fmt.parseInt(u32, std.mem.trim(u8, text[history_cmd.len..], " "), 10) catch 10
        else
            10;
        const limit = @min(n, 50);

        const rows = try store.queryMessages(ctx.io, ctx.allocator, peer_id, limit);
        defer {
            for (rows) |r| {
                ctx.allocator.free(r.message);
                if (r.media_type) |mt| ctx.allocator.free(mt);
                if (r.media_data) |md| ctx.allocator.free(md);
            }
            ctx.allocator.free(rows);
        }

        if (rows.len == 0) {
            try msg.reply("no stored messages for this chat yet");
            return;
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(ctx.allocator);
        const header = try std.fmt.allocPrint(ctx.allocator, "last {d} stored messages:\n", .{rows.len});
        defer ctx.allocator.free(header);
        try out.appendSlice(ctx.allocator, header);
        for (rows) |r| {
            const clipped = if (r.message.len > 60) r.message[0..60] else r.message;
            const line = try std.fmt.allocPrint(ctx.allocator, "{d} | {s} | {s}{s}\n", .{
                r.id,
                if (r.out) "out" else "in",
                clipped,
                if (r.message.len > 60) "…" else "",
            });
            defer ctx.allocator.free(line);
            try out.appendSlice(ctx.allocator, line);
        }
        try msg.reply(out.items);
        return;
    }

    // Any other message: reply; the client's store hook persists it.
    if (text.len > 0) try msg.reply("stored ✓");
}

const handlers = &.{
    tz.Msg.handler(onMessage),
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var file_storage = tz.Storage.File.init("bot_store.session");
    var sqlite_store = try db.StoreSqlite.init("bot_store.db");
    defer sqlite_store.deinit();

    const client = try tz.Client(handlers).init(allocator, .{
        .api_id = try std.fmt.parseInt(i32, init.minimal.environ.getPosix("TZ_API_ID") orelse usage(), 10),
        .api_hash = init.minimal.environ.getPosix("TZ_API_HASH") orelse usage(),
        .bot_token = init.minimal.environ.getPosix("TZ_BOT_TOKEN") orelse usage(),
        .storage = file_storage.storage(),
        .store = sqlite_store.store(),
    });
    defer client.deinit();

    try client.run(io);
}

fn usage() noreturn {
    std.log.err("usage: TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> ./bot_store", .{});
    std.process.exit(1);
}
