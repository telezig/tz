const std = @import("std");
const Connector = @import("Connector.zig");
const client = @import("client.zig");

pub const types = @import("types");
pub const unions = @import("unions");
pub const functions = @import("functions");

pub const Client = client.Client;
pub const ClientOptions = client.ClientOptions;
pub const Context = @import("Context.zig");
pub const Response = Context.Response;
pub const RpcError = @import("RpcError.zig");
pub const handler = client.handler;

pub const Storage = @import("Storage.zig");

pub const DC = Connector.DC;
pub const default_dcs = Connector.default_dcs;

pub const helpers = @import("helpers.zig");
pub const File = @import("File.zig");
pub const Msg = @import("Msg.zig");

pub const State = @import("State.zig");
pub const PeerCache = State.PeerCache;

pub const crypto = @import("crypto.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("crypto/sha.zig");
    _ = @import("crypto/rsa.zig");
    _ = @import("crypto/dh.zig");
    _ = @import("crypto/aes_ige.zig");
    _ = @import("crypto/aes_ctr.zig");
    _ = @import("mtproto/Session.zig");
    _ = @import("State.zig");
    _ = @import("RpcError.zig");
}
