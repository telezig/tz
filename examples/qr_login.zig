//! qr_login — user account auth via QR code (no phone number needed).
//!
//! usage: TZ_API_ID=<id> TZ_API_HASH=<hash> zig build qr-login
//!
//! prints a tg://login?token=... URL on each refresh; scan it with the
//! official Telegram app (Settings → Devices → Link Desktop Device).

const std = @import("std");
const tz = @import("tz");

pub const std_options: std.Options = .{ .log_level = .info };

fn onNewMessage(msg: tz.Msg) !void {
    if (msg.text().len == 0) return;
    std.log.info("msg: {s}", .{msg.text()});
}

const Client = tz.Client(&.{
    tz.Msg.handler(onNewMessage),
});

fn showQrUrl(url: []const u8) !void {
    std.log.info("scan this URL with Telegram (Settings → Devices → Link Desktop Device):\n{s}", .{url});
}

fn userAuth(ctx: tz.Context) !void {
    try ctx.loginQr(showQrUrl);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file_storage = tz.Storage.File.init("qr_login.session");

    const client = try Client.init(allocator, .{
        .api_id = try std.fmt.parseInt(i32, init.environ.getPosix("TZ_API_ID") orelse usage(), 10),
        .api_hash = init.environ.getPosix("TZ_API_HASH") orelse usage(),
        .auth_fn = userAuth,
        .storage = file_storage.storage(),
    });
    defer client.deinit();

    try client.run(io);
}

fn usage() noreturn {
    std.log.err("usage: TZ_API_ID=<id> TZ_API_HASH=<hash> ./qr_login", .{});
    std.process.exit(1);
}
