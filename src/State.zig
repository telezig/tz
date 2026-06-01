//! Update state and gap tracking for a single account.
//!
//! Holds the persistent timestamps (`pts`/`qts`/`seq`/`date`) and decides, per
//! incoming update, whether it can be applied in order, is a duplicate, or opens
//! a gap that must be recovered via `updates.getDifference` /
//! `updates.getChannelDifference`. See
//! <https://core.telegram.org/api/updates#message-related-event-sequences>.
//!
//! Three independent sequences are tracked, mirroring grammers/gotd:
//!   - `common`    — account-wide pts (1:1 chats, small groups)
//!   - `secondary` — account-wide qts (secret chats, bot updates)
//!   - `channel`   — per-channel pts (broadcast/megagroup/supergroup)
//!
//! `common` and `secondary` gaps share a single `updates.getDifference` request,
//! so they share the `getting_diff` flag.
//!
//! The runtime-only peer access-hash cache lives here too (`peers`), since it is
//! refreshed from the same users/chats that accompany updates and difference
//! results. It is not persisted.

const std = @import("std");
const types = @import("types");
const unions = @import("unions");
const functions = @import("functions");
const State = @This();
const ulog = std.log.scoped(.updates);

pub const ChannelState = struct { pts: i32, access_hash: i64 };

/// Which of the three update sequences an update belongs to.
pub const Entry = union(enum) {
    common,
    secondary,
    channel: i64,
};

pub const PtsInfo = struct {
    entry: Entry,
    pts: i32,
    count: i32,
};

/// A normalized `updates`/`updatesCombined` (or single-update) container.
/// `seq_start == 0` means "ignore seq" (short updates, difference results).
pub const Container = struct {
    date: i32 = 0,
    seq: i32 = 0,
    seq_start: i32 = 0,
    updates: []const unions.Update,
};

fn messageChannelId(msg: unions.Message) ?i64 {
    const peer = switch (msg) {
        .Message => |m| m.peer_id,
        .MessageService => |m| m.peer_id,
        .MessageEmpty => |m| m.peer_id.value orelse return null,
    };
    return switch (peer) {
        .PeerChannel => |pc| pc.channel_id,
        else => null,
    };
}

/// Unwrap a field that may be either a plain integer or a `tl.Flag(..)`-wrapped
/// optional. Returns null when the value is an absent optional flag.
fn flagValue(comptime V: type, v: anytype) ?V {
    const F = @TypeOf(v);
    if (F == V) return v;
    // tl.Flag(..) wrappers expose a `.value` of type `?V`.
    if (@hasField(F, "value")) return v.value;
    return @as(?V, null);
}

/// Classify an update into its sequence and pts. Returns null for updates that
/// carry no ordering information (they may be applied in any order).
///
/// This comptime field-presence heuristic is equivalent to grammers' explicit
/// per-type match: every update with a `qts` field belongs to the secondary
/// sequence, every update with a `pts`/`channel_id` belongs to common/channel,
/// and the two sets are disjoint. `qts` is checked first because some qts
/// updates (e.g. `UpdateChannelParticipant`) also carry a `channel_id` that is
/// not a channel-pts target.
pub fn ptsInfo(u: unions.Update) ?PtsInfo {
    switch (u) {
        inline else => |body, tag| {
            const T = @TypeOf(body);
            if (@typeInfo(T) != .@"struct") return null;
            if (@hasField(T, "qts")) {
                const qts = flagValue(i32, body.qts) orelse return null;
                // Almost all qts updates advance by 1; `botDeleteBusinessMessage`
                // advances by the number of deleted messages.
                const count: i32 = if (@hasField(T, "messages")) @intCast(body.messages.len) else 1;
                return .{ .entry = .secondary, .pts = qts, .count = count };
            }
            if (!@hasField(T, "pts")) return null;
            const pts = flagValue(i32, body.pts) orelse return null;
            const count: i32 = if (@hasField(T, "pts_count")) (flagValue(i32, body.pts_count) orelse 0) else 0;
            if (@hasField(T, "channel_id")) {
                const cid = flagValue(i64, body.channel_id) orelse return null;
                return .{ .entry = .{ .channel = cid }, .pts = pts, .count = count };
            }
            if (tag == .UpdateNewChannelMessage or tag == .UpdateEditChannelMessage) {
                if (messageChannelId(body.message)) |cid|
                    return .{ .entry = .{ .channel = cid }, .pts = pts, .count = count };
            }
            return .{ .entry = .common, .pts = pts, .count = count };
        },
    }
}

pts: i32 = 0,
qts: i32 = 0,
date: i32 = 0,
seq: i32 = 0,
channels: std.AutoHashMapUnmanaged(i64, ChannelState) = .empty,

/// common/secondary difference fetch pending (shared `updates.getDifference`).
getting_diff: bool = false,
/// channels with a pending difference fetch.
getting_channel_diff: std.AutoHashMapUnmanaged(i64, void) = .empty,

/// Runtime-only peer access-hash cache (not persisted).
peers: PeerCache = .{},

pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
    self.channels.deinit(gpa);
    self.getting_channel_diff.deinit(gpa);
    self.peers.deinit(gpa);
}

const blob_version: u16 = 1;

pub fn serialize(self: *const State, w: *std.Io.Writer) !void {
    try w.writeInt(u16, blob_version, .little);
    try w.writeInt(i32, self.pts, .little);
    try w.writeInt(i32, self.qts, .little);
    try w.writeInt(i32, self.date, .little);
    try w.writeInt(i32, self.seq, .little);
    try w.writeInt(u32, self.channels.count(), .little);
    var it = self.channels.iterator();
    while (it.next()) |kv| {
        try w.writeInt(i64, kv.key_ptr.*, .little);
        try w.writeInt(i32, kv.value_ptr.pts, .little);
        try w.writeInt(i64, kv.value_ptr.access_hash, .little);
    }
}

/// On failure the caller should reset to an empty State (corrupt blob).
pub fn deserialize(self: *State, gpa: std.mem.Allocator, r: *std.Io.Reader) !void {
    if (try r.takeInt(u16, .little) != blob_version) return error.UnsupportedVersion;
    self.pts = try r.takeInt(i32, .little);
    self.qts = try r.takeInt(i32, .little);
    self.date = try r.takeInt(i32, .little);
    self.seq = try r.takeInt(i32, .little);
    const count = try r.takeInt(u32, .little);
    for (0..count) |_| {
        const id = try r.takeInt(i64, .little);
        const pts = try r.takeInt(i32, .little);
        const ah = try r.takeInt(i64, .little);
        try self.channels.put(gpa, id, .{ .pts = pts, .access_hash = ah });
    }
}

test "serialize/deserialize roundtrip" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 100;
    st.qts = 5;
    st.date = 1234;
    st.seq = 7;
    try st.channels.put(gpa, 555, .{ .pts = 42, .access_hash = 888 });

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try st.serialize(&aw.writer);

    var st2 = State{};
    defer st2.deinit(gpa);
    var r: std.Io.Reader = .fixed(aw.written());
    try st2.deserialize(gpa, &r);

    try std.testing.expectEqual(@as(i32, 100), st2.pts);
    try std.testing.expectEqual(@as(i32, 5), st2.qts);
    try std.testing.expectEqual(@as(i32, 7), st2.seq);
    try std.testing.expectEqual(@as(i32, 42), st2.channels.get(555).?.pts);
    try std.testing.expectEqual(@as(i64, 888), st2.channels.get(555).?.access_hash);
}

test "ptsInfo: common message update" {
    const u = unions.Update{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 50,
        .pts_count = 1,
    } };
    const info = State.ptsInfo(u).?;
    try std.testing.expectEqual(Entry.common, info.entry);
    try std.testing.expectEqual(@as(i32, 50), info.pts);
    try std.testing.expectEqual(@as(i32, 1), info.count);
}

test "ptsInfo: qts update routes to secondary" {
    const u = unions.Update{ .UpdateBotStopped = .{
        .user_id = 1,
        .date = 0,
        .stopped = true,
        .qts = 200,
    } };
    const info = State.ptsInfo(u).?;
    try std.testing.expectEqual(Entry.secondary, info.entry);
    try std.testing.expectEqual(@as(i32, 200), info.pts);
    try std.testing.expectEqual(@as(i32, 1), info.count);
}

test "ptsInfo: qts wins over channel_id" {
    // UpdateChannelParticipant carries both channel_id and qts; it belongs to
    // the secondary (qts) sequence, NOT the channel pts sequence.
    const u = unions.Update{ .UpdateChannelParticipant = .{
        .channel_id = 999,
        .date = 0,
        .actor_id = 1,
        .user_id = 2,
        .qts = 77,
    } };
    const info = State.ptsInfo(u).?;
    try std.testing.expectEqual(Entry.secondary, info.entry);
    try std.testing.expectEqual(@as(i32, 77), info.pts);
}

test "ptsInfo: channel update via explicit channel_id" {
    const u = unions.Update{ .UpdateDeleteChannelMessages = .{
        .channel_id = 999,
        .messages = &.{},
        .pts = 12,
        .pts_count = 1,
    } };
    const info = State.ptsInfo(u).?;
    try std.testing.expectEqual(@as(i64, 999), info.entry.channel);
    try std.testing.expectEqual(@as(i32, 12), info.pts);
}

test "ptsInfo: channel message via message.peer_id" {
    const u = unions.Update{ .UpdateNewChannelMessage = .{
        .message = .{ .Message = .{
            .id = 1,
            .peer_id = .{ .PeerChannel = .{ .channel_id = 321 } },
            .date = 0,
            .message = "hi",
        } },
        .pts = 8,
        .pts_count = 1,
    } };
    const info = State.ptsInfo(u).?;
    try std.testing.expectEqual(@as(i64, 321), info.entry.channel);
}

test "ptsInfo: no pts returns null" {
    const u = unions.Update{ .UpdateChannelUserTyping = .{
        .channel_id = 1,
        .from_id = .{ .PeerUser = .{ .user_id = 2 } },
        .action = .{ .SendMessageTypingAction = .{} },
    } };
    try std.testing.expect(State.ptsInfo(u) == null);
}

pub const ProcessResult = struct {
    /// updates ready to apply, in confirmed order (arena-owned).
    applied: []unions.Update,
};

fn localPts(self: *State, entry: Entry) ?i32 {
    // A pts/qts of 0 means "no baseline yet". Real timestamps are >= 1, and
    // getDifference from 0 is rejected (PERSISTENT_TIMESTAMP_EMPTY), so we treat
    // 0 as unknown — the first pts-bearing update seeds it instead of gapping.
    // For channels the access_hash may already be recorded with pts == 0.
    return switch (entry) {
        .common => if (self.pts == 0) null else self.pts,
        .secondary => if (self.qts == 0) null else self.qts,
        .channel => |id| if (self.channels.get(id)) |c| (if (c.pts == 0) null else c.pts) else null,
    };
}

fn setLocalPts(self: *State, gpa: std.mem.Allocator, entry: Entry, pts: i32) !void {
    switch (entry) {
        .common => self.pts = pts,
        .secondary => self.qts = pts,
        .channel => |id| {
            const gop = try self.channels.getOrPut(gpa, id);
            if (gop.found_existing) {
                gop.value_ptr.pts = pts;
            } else {
                gop.value_ptr.* = .{ .pts = pts, .access_hash = 0 };
            }
        },
    }
}

fn markGap(self: *State, gpa: std.mem.Allocator, entry: Entry) !void {
    switch (entry) {
        // common and secondary share a single updates.getDifference request.
        .common, .secondary => self.getting_diff = true,
        .channel => |id| try self.getting_channel_diff.put(gpa, id, {}),
    }
}

fn lessByPts(_: void, a: unions.Update, b: unions.Update) bool {
    const pa = if (ptsInfo(a)) |i| i.pts - i.count else std.math.minInt(i32);
    const pb = if (ptsInfo(b)) |i| i.pts - i.count else std.math.minInt(i32);
    return pa < pb;
}

/// Process a container of socket updates: checks `seq`, sorts by pts, and applies
/// those without gaps. On a gap, marks the corresponding entry for difference
/// recovery and skips the update (it will be redelivered by getDifference).
///
/// After a global pre-sort, any in-batch gap cannot be filled by a later update
/// in the same batch (their pts are strictly higher), so a gap is marked
/// immediately rather than buffered.
pub fn process(
    self: *State,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    c: Container,
) !ProcessResult {
    // > For [updates/updatesCombined] there is need to check seq. For all other
    // > Updates constructors there is no need to check seq (seq_start == 0).
    if (c.seq_start != 0) {
        const expected_seq = self.seq + 1;
        if (expected_seq < c.seq_start) {
            ulog.debug("seq gap: local={} remote seq_start={}", .{ self.seq, c.seq_start });
            self.getting_diff = true;
            return .{ .applied = &.{} };
        } else if (expected_seq > c.seq_start) {
            ulog.debug("seq already handled: local={} remote seq_start={}", .{ self.seq, c.seq_start });
            return .{ .applied = &.{} };
        }
    }

    const sorted = try arena.dupe(unions.Update, c.updates);
    std.sort.pdq(unions.Update, sorted, {}, lessByPts);

    var applied: std.ArrayListUnmanaged(unions.Update) = .empty;
    var gapped = false;
    for (sorted) |u| {
        const tag = @tagName(u);

        // UpdateChannelTooLong is a "you are too far behind" signal: it must
        // always force a channel difference, regardless of whether it carries a
        // pts. Handle it before ptsInfo (whose pts is optional here).
        if (std.meta.activeTag(u) == .UpdateChannelTooLong) {
            const t = u.UpdateChannelTooLong;
            if (flagValue(i32, t.pts)) |pts| try self.setLocalPts(gpa, .{ .channel = t.channel_id }, pts);
            ulog.debug("channel too long {} -> get difference", .{t.channel_id});
            try self.markGap(gpa, .{ .channel = t.channel_id });
            gapped = true;
            continue;
        }

        const info = ptsInfo(u) orelse {
            ulog.debug("apply (no pts) {s}", .{tag});
            try applied.append(arena, u);
            continue;
        };
        const gapping = switch (info.entry) {
            .common, .secondary => self.getting_diff,
            .channel => |id| self.getting_channel_diff.contains(id),
        };
        if (gapping) {
            ulog.debug("skip (gap pending) {s} entry={} pts={}", .{ tag, info.entry, info.pts });
            continue;
        }

        const local = self.localPts(info.entry) orelse {
            // First sighting of this entry: no baseline to detect a gap against,
            // so adopt this pts as the starting point and apply directly.
            ulog.debug("seed (new entry) {s} entry={} pts={}", .{ tag, info.entry, info.pts });
            try self.setLocalPts(gpa, info.entry, info.pts);
            try applied.append(arena, u);
            continue;
        };
        const expected = local + info.count;
        if (info.pts <= local) {
            ulog.debug("dup {s} entry={} pts={} <= local={}", .{ tag, info.entry, info.pts, local });
            continue;
        } else if (info.pts == expected) {
            ulog.debug("apply {s} entry={} pts={} (local {} -> {})", .{ tag, info.entry, info.pts, local, info.pts });
            try self.setLocalPts(gpa, info.entry, info.pts);
            try applied.append(arena, u);
        } else {
            ulog.debug("gap {s} entry={} pts={} count={} local={} expected={}", .{
                tag, info.entry, info.pts, info.count, local, expected,
            });
            try self.markGap(gpa, info.entry);
            gapped = true;
        }
    }

    // > If the updates were applied, local Updates state must be updated with
    // > seq (unless 0) and date from the constructor.
    if (applied.items.len > 0 and !gapped) {
        if (c.date != 0) self.date = c.date;
        if (c.seq != 0) self.seq = c.seq;
    }

    return .{ .applied = try applied.toOwnedSlice(arena) };
}

test "process: in-order applies, advances pts and seq" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 10;
    st.seq = 3;
    const ups = [_]unions.Update{.{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 11,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .date = 999, .seq = 4, .seq_start = 4, .updates = &ups });
    try std.testing.expectEqual(@as(usize, 1), res.applied.len);
    try std.testing.expectEqual(@as(i32, 11), st.pts);
    try std.testing.expectEqual(@as(i32, 4), st.seq);
    try std.testing.expectEqual(@as(i32, 999), st.date);
    try std.testing.expect(!st.getting_diff);
}

test "process: gap marks getting_diff, does not apply" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 10;
    const ups = [_]unions.Update{.{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 15,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(st.getting_diff);
    try std.testing.expectEqual(@as(i32, 10), st.pts);
}

test "process: qts update advances qts, not pts" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 50;
    st.qts = 10;
    const ups = [_]unions.Update{.{ .UpdateBotStopped = .{
        .user_id = 1,
        .date = 0,
        .stopped = true,
        .qts = 11,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 1), res.applied.len);
    try std.testing.expectEqual(@as(i32, 11), st.qts);
    try std.testing.expectEqual(@as(i32, 50), st.pts); // untouched
    try std.testing.expect(!st.getting_diff);
}

test "process: qts gap marks getting_diff, leaves pts" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 50;
    st.qts = 10;
    const ups = [_]unions.Update{.{ .UpdateBotStopped = .{
        .user_id = 1,
        .date = 0,
        .stopped = true,
        .qts = 20,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(st.getting_diff);
    try std.testing.expectEqual(@as(i32, 10), st.qts);
}

test "process: seq gap skips batch and marks getting_diff" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 10;
    st.seq = 5;
    const ups = [_]unions.Update{.{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 11,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    // local seq 5, expected next 6, but remote seq_start is 8 -> gap.
    const res = try st.process(gpa, arena.allocator(), .{ .seq = 8, .seq_start = 8, .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(st.getting_diff);
    try std.testing.expectEqual(@as(i32, 10), st.pts); // batch not processed
    try std.testing.expectEqual(@as(i32, 5), st.seq); // not advanced
}

test "process: stale seq batch ignored" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 10;
    st.seq = 5;
    const ups = [_]unions.Update{.{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 11,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    // seq_start 4 <= local seq 5 -> already handled, ignore without gap.
    const res = try st.process(gpa, arena.allocator(), .{ .seq = 4, .seq_start = 4, .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(!st.getting_diff);
    try std.testing.expectEqual(@as(i32, 10), st.pts);
}

test "process: duplicate (pts <= local) skipped" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.pts = 20;
    const ups = [_]unions.Update{.{ .UpdateNewMessage = .{
        .message = .{ .MessageEmpty = .{ .id = 1 } },
        .pts = 18,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(!st.getting_diff);
}

test "process: UpdateChannelTooLong forces channel difference (with pts)" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    var too_long = types.UpdateChannelTooLong{ .channel_id = 444 };
    too_long.pts = .some(30);
    const ups = [_]unions.Update{.{ .UpdateChannelTooLong = too_long }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(st.getting_channel_diff.contains(444));
    try std.testing.expectEqual(@as(i32, 30), st.channels.get(444).?.pts);
}

test "process: UpdateChannelTooLong forces channel difference (no pts)" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    const ups = [_]unions.Update{.{ .UpdateChannelTooLong = .{ .channel_id = 444 } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 0), res.applied.len);
    try std.testing.expect(st.getting_channel_diff.contains(444));
}

test "process: first sighting of a channel seeds pts and applies (no diff)" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    const ups = [_]unions.Update{.{ .UpdateDeleteChannelMessages = .{
        .channel_id = 777,
        .messages = &.{},
        .pts = 5,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 1), res.applied.len);
    try std.testing.expect(!st.getting_channel_diff.contains(777));
    try std.testing.expectEqual(@as(i32, 5), st.channels.get(777).?.pts);
}

test "process: channel with recorded access_hash but pts=0 seeds, not gaps" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    try st.channels.put(gpa, 888, .{ .pts = 0, .access_hash = 42 });
    const ups = [_]unions.Update{.{ .UpdateDeleteChannelMessages = .{
        .channel_id = 888,
        .messages = &.{},
        .pts = 5,
        .pts_count = 1,
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 1), res.applied.len);
    try std.testing.expect(!st.getting_channel_diff.contains(888));
    try std.testing.expectEqual(@as(i32, 5), st.channels.get(888).?.pts);
    try std.testing.expectEqual(@as(i64, 42), st.channels.get(888).?.access_hash); // preserved
}

test "process: no-pts update always applied" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    const ups = [_]unions.Update{.{ .UpdateChannelUserTyping = .{
        .channel_id = 1,
        .from_id = .{ .PeerUser = .{ .user_id = 2 } },
        .action = .{ .SendMessageTypingAction = .{} },
    } }};
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const res = try st.process(gpa, arena.allocator(), .{ .updates = &ups });
    try std.testing.expectEqual(@as(usize, 1), res.applied.len);
}

pub fn setState(self: *State, st: types.UpdatesState) void {
    self.pts = st.pts;
    self.qts = st.qts;
    self.date = st.date;
    self.seq = st.seq;
}

pub const Request = union(enum) {
    common: functions.updates.GetDifference,
    channel: struct { id: i64, req: functions.updates.GetChannelDifference },
};

/// Stop tracking a channel entirely — drops both the pending gap and its pts state.
/// Used when the server reports the channel is inaccessible (CHANNEL_INVALID), where
/// retrying the difference would loop forever.
pub fn dropChannel(self: *State, id: i64) void {
    _ = self.getting_channel_diff.remove(id);
    _ = self.channels.remove(id);
}

/// Returns a pending difference request if any gap is set. Common takes priority.
/// For channel requests the caller must resolve access_hash (channel field is Empty here).
pub fn takeDifferenceRequest(self: *State) ?Request {
    if (self.getting_diff) {
        return .{ .common = .{ .pts = self.pts, .date = self.date, .qts = self.qts } };
    }
    var it = self.getting_channel_diff.keyIterator();
    if (it.next()) |id_ptr| {
        const id = id_ptr.*;
        const cs = self.channels.get(id) orelse return null;
        return .{ .channel = .{ .id = id, .req = .{
            .channel = .{ .InputChannelEmpty = .{} },
            .filter = .{ .ChannelMessagesFilterEmpty = .{} },
            .pts = cs.pts,
            .limit = 100,
        } } };
    }
    return null;
}

pub const DiffApplied = struct {
    updates: []unions.Update,
    users: []const unions.User,
    chats: []const unions.Chat,
    /// true if this was a partial slice and the difference loop must continue.
    has_more: bool,
};

/// Wraps new_messages as UpdateNewMessage (pts=0; state already advanced via setState)
/// and concatenates other_updates. These are dispatched directly (not re-run through process).
fn diffToUpdates(
    arena: std.mem.Allocator,
    new_messages: []const unions.Message,
    other: []const unions.Update,
) ![]unions.Update {
    var list: std.ArrayListUnmanaged(unions.Update) = .empty;
    for (new_messages) |m| {
        try list.append(arena, .{ .UpdateNewMessage = .{ .message = m, .pts = 0, .pts_count = 0 } });
    }
    try list.appendSlice(arena, other);
    return list.toOwnedSlice(arena);
}

pub fn applyDifference(
    self: *State,
    arena: std.mem.Allocator,
    diff: unions.UpdatesDifference,
) !DiffApplied {
    switch (diff) {
        .UpdatesDifferenceEmpty => |e| {
            self.date = e.date;
            self.seq = e.seq;
            self.getting_diff = false;
            return .{ .updates = &.{}, .users = &.{}, .chats = &.{}, .has_more = false };
        },
        .UpdatesDifference => |d| {
            self.setState(d.state);
            self.getting_diff = false;
            const ups = try diffToUpdates(arena, d.new_messages, d.other_updates);
            return .{ .updates = ups, .users = d.users, .chats = d.chats, .has_more = false };
        },
        .UpdatesDifferenceSlice => |d| {
            self.setState(d.intermediate_state);
            const ups = try diffToUpdates(arena, d.new_messages, d.other_updates);
            return .{ .updates = ups, .users = d.users, .chats = d.chats, .has_more = true };
        },
        .UpdatesDifferenceTooLong => |d| {
            self.pts = d.pts;
            return .{ .updates = &.{}, .users = &.{}, .chats = &.{}, .has_more = true };
        },
    }
}

test "setState then takeDifferenceRequest none when no gap" {
    var st = State{};
    defer st.deinit(std.testing.allocator);
    st.setState(.{ .pts = 5, .qts = 1, .date = 100, .seq = 2, .unread_count = 0 });
    try std.testing.expectEqual(@as(i32, 5), st.pts);
    try std.testing.expect(st.takeDifferenceRequest() == null);
}

test "common gap produces GetDifference request" {
    var st = State{};
    defer st.deinit(std.testing.allocator);
    st.setState(.{ .pts = 5, .qts = 1, .date = 100, .seq = 2, .unread_count = 0 });
    st.getting_diff = true;
    const req = st.takeDifferenceRequest().?;
    try std.testing.expectEqual(@as(i32, 5), req.common.pts);
    try std.testing.expectEqual(@as(i32, 1), req.common.qts);
    try std.testing.expectEqual(@as(i32, 100), req.common.date);
}

test "applyDifference advances state and clears gap" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    st.setState(.{ .pts = 5, .qts = 1, .date = 100, .seq = 2, .unread_count = 0 });
    st.getting_diff = true;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const diff = unions.UpdatesDifference{ .UpdatesDifference = .{
        .new_messages = &.{},
        .new_encrypted_messages = &.{},
        .other_updates = &.{},
        .chats = &.{},
        .users = &.{},
        .state = .{ .pts = 9, .qts = 1, .date = 200, .seq = 3, .unread_count = 0 },
    } };
    const res = try st.applyDifference(arena.allocator(), diff);
    try std.testing.expectEqual(@as(i32, 9), st.pts);
    try std.testing.expect(!st.getting_diff);
    _ = res;
}

fn setChannelPts(self: *State, gpa: std.mem.Allocator, id: i64, pts: i32) !void {
    const gop = try self.channels.getOrPut(gpa, id);
    if (gop.found_existing) {
        gop.value_ptr.pts = pts;
    } else {
        gop.value_ptr.* = .{ .pts = pts, .access_hash = 0 };
    }
}

pub fn applyChannelDifference(
    self: *State,
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    channel_id: i64,
    diff: unions.UpdatesChannelDifference,
) !DiffApplied {
    switch (diff) {
        .UpdatesChannelDifferenceEmpty => |d| {
            try self.setChannelPts(gpa, channel_id, d.pts);
            _ = self.getting_channel_diff.remove(channel_id);
            return .{ .updates = &.{}, .users = &.{}, .chats = &.{}, .has_more = false };
        },
        .UpdatesChannelDifference => |d| {
            try self.setChannelPts(gpa, channel_id, d.pts);
            const final = d.final.value != null;
            if (final) _ = self.getting_channel_diff.remove(channel_id);
            const ups = try diffToUpdates(arena, d.new_messages, d.other_updates);
            return .{ .updates = ups, .users = d.users, .chats = d.chats, .has_more = !final };
        },
        .UpdatesChannelDifferenceTooLong => |d| {
            // The fresh baseline pts lives in the embedded dialog; adopt it so
            // the channel does not gap forever. The messages are intentionally
            // dropped (they will be re-fetched on the next difference round if
            // this slice was not final), matching grammers.
            const dl_pts: ?i32 = switch (d.dialog) {
                .Dialog => |dl| flagValue(i32, dl.pts),
                .DialogFolder => null,
            };
            if (dl_pts) |p| try self.setChannelPts(gpa, channel_id, p);
            const final = d.final.value != null;
            if (final) _ = self.getting_channel_diff.remove(channel_id);
            return .{ .updates = &.{}, .users = d.users, .chats = d.chats, .has_more = !final };
        },
    }
}

test "applyChannelDifference advances channel pts and clears gap" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    try st.channels.put(gpa, 77, .{ .pts = 3, .access_hash = 111 });
    try st.getting_channel_diff.put(gpa, 77, {});
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const diff = unions.UpdatesChannelDifference{ .UpdatesChannelDifference = .{
        .final = .some({}),
        .pts = 8,
        .new_messages = &.{},
        .other_updates = &.{},
        .chats = &.{},
        .users = &.{},
    } };
    const res = try st.applyChannelDifference(gpa, arena.allocator(), 77, diff);
    try std.testing.expectEqual(@as(i32, 8), st.channels.get(77).?.pts);
    try std.testing.expect(!st.getting_channel_diff.contains(77));
    try std.testing.expect(!res.has_more);
}

test "non-final channel difference keeps gap for more" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    try st.channels.put(gpa, 77, .{ .pts = 3, .access_hash = 111 });
    try st.getting_channel_diff.put(gpa, 77, {});
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const diff = unions.UpdatesChannelDifference{ .UpdatesChannelDifference = .{
        .pts = 8,
        .new_messages = &.{},
        .other_updates = &.{},
        .chats = &.{},
        .users = &.{},
    } };
    const res = try st.applyChannelDifference(gpa, arena.allocator(), 77, diff);
    try std.testing.expect(res.has_more);
    try std.testing.expect(st.getting_channel_diff.contains(77));
}

test "channelDifferenceTooLong adopts dialog pts and ends when final" {
    const gpa = std.testing.allocator;
    var st = State{};
    defer st.deinit(gpa);
    try st.channels.put(gpa, 77, .{ .pts = 3, .access_hash = 111 });
    try st.getting_channel_diff.put(gpa, 77, {});
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var dlg = types.Dialog{
        .peer = .{ .PeerChannel = .{ .channel_id = 77 } },
        .top_message = 0,
        .read_inbox_max_id = 0,
        .read_outbox_max_id = 0,
        .unread_count = 0,
        .unread_mentions_count = 0,
        .unread_reactions_count = 0,
        .unread_poll_votes_count = 0,
        .notify_settings = .{},
    };
    dlg.pts = .some(50);
    var too_long = types.UpdatesChannelDifferenceTooLong{
        .dialog = .{ .Dialog = dlg },
        .messages = &.{},
        .chats = &.{},
        .users = &.{},
    };
    too_long.final = .some({});
    const diff = unions.UpdatesChannelDifference{ .UpdatesChannelDifferenceTooLong = too_long };
    const res = try st.applyChannelDifference(gpa, arena.allocator(), 77, diff);
    try std.testing.expectEqual(@as(i32, 50), st.channels.get(77).?.pts);
    try std.testing.expect(!st.getting_channel_diff.contains(77));
    try std.testing.expect(!res.has_more);
}

// ---------------------------------------------------------------------------
// Peer access-hash cache (runtime-only; not persisted).
// ---------------------------------------------------------------------------

pub const PeerCache = struct {
    pub const Kind = enum { user, chat, channel };

    pub const CacheEntry = struct {
        access_hash: i64,
        kind: Kind,
        min: bool,
    };

    map: std.AutoHashMapUnmanaged(i64, CacheEntry) = .empty,
    /// username (lowercase, no @) → id.  Keys are gpa-owned.
    username_map: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn deinit(self: *PeerCache, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
        var it = self.username_map.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        self.username_map.deinit(gpa);
    }

    fn put(self: *PeerCache, gpa: std.mem.Allocator, id: i64, e: CacheEntry) !void {
        const gop = try self.map.getOrPut(gpa, id);
        if (gop.found_existing) {
            // min must not overwrite non-min.
            if (e.min and !gop.value_ptr.min) return;
        }
        gop.value_ptr.* = e;
    }

    /// Store a username → id mapping.  `username` is normalized to lowercase
    /// before insertion; no leading `@`.  Silently ignores names longer than 64 bytes.
    pub fn putUsername(self: *PeerCache, gpa: std.mem.Allocator, username: []const u8, id: i64) !void {
        if (username.len == 0 or username.len > 64) return;
        var buf: [64]u8 = undefined;
        const lower = std.ascii.lowerString(buf[0..username.len], username);
        const gop = try self.username_map.getOrPut(gpa, lower);
        if (!gop.found_existing) gop.key_ptr.* = try gpa.dupe(u8, lower);
        gop.value_ptr.* = id;
    }

    pub fn lookupUsername(self: *const PeerCache, username: []const u8) ?i64 {
        if (username.len == 0 or username.len > 64) return null;
        var buf: [64]u8 = undefined;
        const lower = std.ascii.lowerString(buf[0..username.len], username);
        return self.username_map.get(lower);
    }

    pub fn update(
        self: *PeerCache,
        gpa: std.mem.Allocator,
        users: []const unions.User,
        chats: []const unions.Chat,
    ) !void {
        for (users) |u| switch (u) {
            .User => |user| {
                if (user.access_hash.value) |ah|
                    try self.put(gpa, user.id, .{ .access_hash = ah, .kind = .user, .min = user.min.value != null });
                if (user.username.value) |name|
                    try self.putUsername(gpa, name, user.id);
                if (user.usernames.value) |names|
                    for (names) |un| if (un.active.value != null)
                        try self.putUsername(gpa, un.username, user.id);
            },
            else => {},
        };
        for (chats) |c| switch (c) {
            .Channel => |ch| {
                if (ch.access_hash.value) |ah|
                    try self.put(gpa, ch.id, .{ .access_hash = ah, .kind = .channel, .min = ch.min.value != null });
                if (ch.username.value) |name|
                    try self.putUsername(gpa, name, ch.id);
                if (ch.usernames.value) |names|
                    for (names) |un| if (un.active.value != null)
                        try self.putUsername(gpa, un.username, ch.id);
            },
            .Chat => |chat| try self.put(gpa, chat.id, .{ .access_hash = 0, .kind = .chat, .min = false }),
            else => {},
        };
    }

    pub fn inputPeer(self: *const PeerCache, id: i64) ?unions.InputPeer {
        const e = self.map.get(id) orelse return null;
        return switch (e.kind) {
            .user => .{ .InputPeerUser = .{ .user_id = id, .access_hash = e.access_hash } },
            .channel => .{ .InputPeerChannel = .{ .channel_id = id, .access_hash = e.access_hash } },
            .chat => .{ .InputPeerChat = .{ .chat_id = id } },
        };
    }

    pub fn inputUser(self: *const PeerCache, id: i64) ?unions.InputUser {
        const e = self.map.get(id) orelse return null;
        if (e.kind != .user) return null;
        return .{ .InputUser = .{ .user_id = id, .access_hash = e.access_hash } };
    }

    pub fn inputChannel(self: *const PeerCache, id: i64) ?unions.InputChannel {
        const e = self.map.get(id) orelse return null;
        if (e.kind != .channel) return null;
        return .{ .InputChannel = .{ .channel_id = id, .access_hash = e.access_hash } };
    }
};

test "PeerCache: min peer does not overwrite non-min" {
    const gpa = std.testing.allocator;
    var pc = PeerCache{};
    defer pc.deinit(gpa);

    const full = [_]unions.User{.{ .User = .{ .id = 10, .access_hash = .{ .value = 1234 } } }};
    try pc.update(gpa, &full, &.{});
    var min_user = types.User{ .id = 10, .access_hash = .{ .value = 9999 } };
    min_user.min = .some({});
    const min = [_]unions.User{.{ .User = min_user }};
    try pc.update(gpa, &min, &.{});

    const ip = pc.inputPeer(10).?;
    try std.testing.expectEqual(@as(i64, 1234), ip.InputPeerUser.access_hash);
}

test "PeerCache: inputChannel resolves from chats" {
    const gpa = std.testing.allocator;
    var pc = PeerCache{};
    defer pc.deinit(gpa);
    const chats = [_]unions.Chat{.{ .Channel = .{ .id = 77, .access_hash = .{ .value = 555 }, .title = "c", .photo = undefined, .date = 0 } }};
    try pc.update(gpa, &.{}, &chats);
    const ic = pc.inputChannel(77).?;
    try std.testing.expectEqual(@as(i64, 77), ic.InputChannel.channel_id);
    try std.testing.expectEqual(@as(i64, 555), ic.InputChannel.access_hash);
}
