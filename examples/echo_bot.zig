//! echo_bot — echoes every message it receives.
//! usage: TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> zig build echo-bot

const std = @import("std");
const tz = @import("tz");

fn onNewMessage(msg: tz.Msg) !void {
    if (msg.text().len == 0) return;
    try msg.reply(msg.text());
}

const handlers = &.{
    tz.Msg.handler(onNewMessage),
};

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file_storage = tz.Storage.File.init("echo_bot.session");

    const client = try tz.Client(handlers).init(allocator, .{
        .api_id = try std.fmt.parseInt(i32, init.environ.getPosix("TZ_API_ID") orelse usage(), 10),
        .api_hash = init.environ.getPosix("TZ_API_HASH") orelse usage(),
        .bot_token = init.environ.getPosix("TZ_BOT_TOKEN") orelse usage(),
        .storage = file_storage.storage(),
    });
    defer client.deinit();

    try client.run(io);
}

fn usage() noreturn {
    std.log.err("usage: TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> ./echo_bot", .{});
    std.process.exit(1);
}
