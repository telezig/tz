//! user_login — interactive user account auth via auth_fn.
//!
//! usage: TZ_API_ID=<id> TZ_API_HASH=<hash> zig build user-login
//!
//! prompts for phone, login code, and (if enabled) the 2FA password on stdin.
//! note: the password is read in plaintext — hiding terminal echo is left out for
//! brevity. fine for a demo, do better in production.

const std = @import("std");
const tz = @import("tz");
const functions = @import("functions");

// Quiet the per-packet debug logs so they don't interleave with the interactive
// prompts. Bump to .debug if you need to see the wire traffic.
pub const std_options: std.Options = .{ .log_level = .info };

// Remembered across auth_fn invocations: a DC migration (PHONE_MIGRATE) tears down
// and re-runs auth, and we don't want to re-prompt for the phone number each time.
var cached_phone: ?[]u8 = null;

fn onNewMessage(msg: tz.Msg) !void {
    if (msg.text().len == 0) return;
    std.log.info("msg: {s}", .{msg.text()});
}

const Client = tz.Client(&.{
    tz.Msg.handler(onNewMessage),
});

/// Prompt on stderr, read one line from stdin, return an owned, trimmed copy.
fn readLine(allocator: std.mem.Allocator, io: std.Io, in: *std.Io.Reader, label: []const u8) ![]u8 {
    var obuf: [128]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &obuf);
    try ew.interface.writeAll(label);
    try ew.interface.flush();
    // takeDelimiter consumes the '\n'; takeDelimiterExclusive would leave it in the
    // buffer and the next read would return an empty line.
    const line = (try in.takeDelimiter('\n')) orelse return error.EndOfInput;
    return allocator.dupe(u8, std.mem.trimEnd(u8, line, "\r \t"));
}

// auth_fn now receives a typed Context — no *anyopaque cast. call TL functions
// through ctx.call / ctx.exec exactly like in an update handler.
fn userAuth(ctx: tz.Context) !void {
    var ibuf: [512]u8 = undefined;
    var fr = std.Io.File.stdin().reader(ctx.io, &ibuf);
    const in = &fr.interface;

    // prompt once; reuse on later auth_fn runs (e.g. after a DC migration).
    const phone = cached_phone orelse blk: {
        const p = try readLine(ctx.allocator, ctx.io, in, "phone number (e.g. +12345678900): ");
        cached_phone = p;
        break :blk p;
    };

    // step 1: request a code. phone_code_hash comes back in the response.
    const sent = try ctx.call(functions.auth.SendCode{
        .phone_number = phone,
        .api_id = ctx.api_id,
        .api_hash = ctx.api_hash,
        .settings = .{},
    });
    defer sent.deinit();
    const phone_code_hash = switch (sent.value) {
        .AuthSentCode => |s| s.phone_code_hash,
        .AuthSentCodeSuccess => return, // already signed in, no code needed
        .AuthSentCodePaymentRequired => return error.PaymentRequired,
    };

    // step 2: sign in with the code. a wrong code re-prompts in place — the lib
    // surfaces PHONE_CODE_INVALID distinctly so we don't tear down the connection.
    while (true) {
        const code = try readLine(ctx.allocator, ctx.io, in, "login code: ");
        defer ctx.allocator.free(code);

        ctx.exec(functions.auth.SignIn{
            .phone_number = phone,
            .phone_code_hash = phone_code_hash,
            .phone_code = .some(code),
        }) catch |err| switch (err) {
            error.PhoneCodeInvalid => {
                std.log.warn("invalid code, try again", .{});
                continue;
            },
            error.SessionPasswordNeeded => return signIn2FA(ctx, in),
            else => return err,
        };
        return; // signed in without 2FA
    }
}

fn signIn2FA(ctx: tz.Context, in: *std.Io.Reader) !void {
    // a wrong password re-prompts in place (PASSWORD_HASH_INVALID). GetPassword is
    // re-fetched each attempt because the SRP challenge is single-use.
    while (true) {
        const password = try readLine(ctx.allocator, ctx.io, in, "2FA password: ");
        defer ctx.allocator.free(password);

        const pwd_resp = try ctx.call(functions.account.GetPassword{});
        defer pwd_resp.deinit();
        const pwd = pwd_resp.value;

        const algo = switch (pwd.current_algo.value orelse return error.NoPassword) {
            .PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow => |a| a,
            else => return error.UnsupportedPasswordAlgo,
        };

        const answer = try tz.crypto.srp.compute(
            ctx.allocator,
            ctx.io,
            algo.salt1,
            algo.salt2,
            algo.g,
            algo.p,
            pwd.srp_B.value orelse return error.NoPassword,
            password,
        );

        ctx.exec(functions.auth.CheckPassword{
            .password = .{ .InputCheckPasswordSRP = .{
                .srp_id = pwd.srp_id.value orelse return error.NoPassword,
                .A = &answer.A,
                .M1 = &answer.M1,
            } },
        }) catch |err| switch (err) {
            error.PasswordHashInvalid => {
                std.log.warn("wrong password, try again", .{});
                continue;
            },
            else => return err,
        };
        return; // 2FA accepted
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    defer if (cached_phone) |p| allocator.free(p);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file_storage = tz.Storage.File.init("user_login.session");

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
    std.log.err("usage: TZ_API_ID=<id> TZ_API_HASH=<hash> ./user_login", .{});
    std.process.exit(1);
}
