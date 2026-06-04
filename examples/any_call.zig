//! any_call — demonstrates direct ctx.call() / ctx.exec() without helpers.
//!
//! Two handlers on the same update type, split by functional boundary:
//!   onCommand  — /whoami (fetch own user) and /delete (delete command message)
//!   onEcho     — everything else: echo with a quote reply
//!
//! usage: TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> zig build any-call

const std = @import("std");
const tz = @import("tz");
const tg = tz.types;
const f = tz.functions;

fn onCommand(msg: tz.Msg) !void {
    if (msg.text().len == 0 or msg.text()[0] != '/') return;
    const peer = msg.peer() orelse return;
    if (msg.is("/whoami")) {
        var id_input = [_]tz.unions.InputUser{.{ .InputUserSelf = .{} }};
        const users_resp = try msg.ctx.call(f.users.GetUsers{ .id = &id_input });
        defer users_resp.deinit();
        const user = switch (users_resp.value[0]) {
            .User => |u| u,
            else => return,
        };
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "id={} name={s}", .{
            user.id,
            user.first_name.value orelse "(none)",
        });
        try msg.ctx.exec(f.messages.SendMessage{ .peer = peer, .message = text });
    } else if (msg.is("/delete")) {
        var ids = [_]i32{msg.id()};
        try msg.ctx.exec(f.messages.DeleteMessages{ .id = &ids });
    }
}

fn onEcho(msg: tz.Msg) !void {
    if (msg.text().len == 0 or msg.text()[0] == '/') return;
    try msg.reply(msg.text());
}

const handlers = &.{
    tz.Msg.handler(onCommand),
    tz.Msg.handler(onEcho),
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var file_storage = tz.Storage.File.init("any_call.session");

    const client = try tz.Client(handlers).init(allocator, .{
        .api_id = try std.fmt.parseInt(i32, init.minimal.environ.getPosix("TZ_API_ID") orelse usage(), 10),
        .api_hash = init.minimal.environ.getPosix("TZ_API_HASH") orelse usage(),
        .bot_token = init.minimal.environ.getPosix("TZ_BOT_TOKEN") orelse usage(),
        .storage = file_storage.storage(),
    });
    defer client.deinit();

    try client.run(io);
}

fn usage() noreturn {
    std.log.err("usage: TZ_API_ID=<id> TZ_API_HASH=<hash> TZ_BOT_TOKEN=<token> ./any_call", .{});
    std.process.exit(1);
}
