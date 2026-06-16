const FormattedText = @This();
const std = @import("std");
const types = @import("types");
const unions = @import("unions");

pub fn utf16Len(s: []const u8) i32 {
    var len: i32 = 0;
    const view = std.unicode.Utf8View.initUnchecked(s);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        len += if (cp >= 0x10000) 2 else 1;
    }
    return len;
}

allocator: std.mem.Allocator,
text: std.ArrayList(u8),
entities: std.ArrayList(unions.MessageEntity),

pub fn init(allocator: std.mem.Allocator) FormattedText {
    return .{
        .allocator = allocator,
        .text = .empty,
        .entities = .empty,
    };
}

pub fn deinit(self: *FormattedText) void {
    self.text.deinit(self.allocator);
    self.entities.deinit(self.allocator);
}

fn offset(self: *const FormattedText) i32 {
    return utf16Len(self.text.items);
}

pub fn plain(self: *FormattedText, s: []const u8) !void {
    try self.text.appendSlice(self.allocator, s);
}

pub fn bold(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityBold = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn italic(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityItalic = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn code(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityCode = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn pre(self: *FormattedText, s: []const u8, language: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityPre = .{ .offset = off, .length = utf16Len(s), .language = language } });
}

pub fn link(self: *FormattedText, s: []const u8, url: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityTextUrl = .{ .offset = off, .length = utf16Len(s), .url = url } });
}

pub fn underline(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityUnderline = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn strike(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityStrike = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn spoiler(self: *FormattedText, s: []const u8) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntitySpoiler = .{ .offset = off, .length = utf16Len(s) } });
}

pub fn customEmoji(self: *FormattedText, s: []const u8, document_id: i64) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityCustomEmoji = .{ .offset = off, .length = utf16Len(s), .document_id = document_id } });
}

pub fn mentionName(self: *FormattedText, s: []const u8, user_id: i64) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityMentionName = .{ .offset = off, .length = utf16Len(s), .user_id = user_id } });
}

pub fn blockquote(self: *FormattedText, s: []const u8, collapsed: bool) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityBlockquote = .{
        .offset = off,
        .length = utf16Len(s),
        .collapsed = if (collapsed) .some({}) else .none,
    } });
}

pub const DateOptions = struct {
    relative: bool = false,
    short_time: bool = false,
    long_time: bool = false,
    short_date: bool = false,
    long_date: bool = false,
    day_of_week: bool = false,
};

pub fn formattedDate(self: *FormattedText, s: []const u8, date: i32, opts: DateOptions) !void {
    const off = self.offset();
    try self.text.appendSlice(self.allocator, s);
    try self.entities.append(self.allocator, .{ .MessageEntityFormattedDate = .{
        .offset = off,
        .length = utf16Len(s),
        .date = date,
        .relative = if (opts.relative) .some({}) else .none,
        .short_time = if (opts.short_time) .some({}) else .none,
        .long_time = if (opts.long_time) .some({}) else .none,
        .short_date = if (opts.short_date) .some({}) else .none,
        .long_date = if (opts.long_date) .some({}) else .none,
        .day_of_week = if (opts.day_of_week) .some({}) else .none,
    } });
}

test "utf16Len" {
    try std.testing.expectEqual(@as(i32, 0), utf16Len(""));
    try std.testing.expectEqual(@as(i32, 5), utf16Len("hello"));
    try std.testing.expectEqual(@as(i32, 2), utf16Len("中文"));
    try std.testing.expectEqual(@as(i32, 2), utf16Len("😀"));
    try std.testing.expectEqual(@as(i32, 4), utf16Len("hi😀"));
}

test "FormattedText entity offsets" {
    const a = std.testing.allocator;
    var ft = FormattedText.init(a);
    defer ft.deinit();

    try ft.plain("hello ");
    try ft.bold("world");

    try std.testing.expectEqualStrings("hello world", ft.text.items);
    try std.testing.expectEqual(@as(usize, 1), ft.entities.items.len);
    const e = switch (ft.entities.items[0]) {
        .MessageEntityBold => |b| b,
        else => return error.WrongEntityType,
    };
    try std.testing.expectEqual(@as(i32, 6), e.offset);
    try std.testing.expectEqual(@as(i32, 5), e.length);
}

test "FormattedText emoji offset" {
    const a = std.testing.allocator;
    var ft = FormattedText.init(a);
    defer ft.deinit();

    try ft.plain("😀");
    try ft.bold("hi");

    try std.testing.expectEqual(@as(usize, 1), ft.entities.items.len);
    const e = switch (ft.entities.items[0]) {
        .MessageEntityBold => |b| b,
        else => return error.WrongEntityType,
    };
    try std.testing.expectEqual(@as(i32, 2), e.offset);
    try std.testing.expectEqual(@as(i32, 2), e.length);
}

test "FormattedText multiple entities" {
    const a = std.testing.allocator;
    var ft = FormattedText.init(a);
    defer ft.deinit();

    try ft.bold("a");
    try ft.plain("b");
    try ft.italic("c");

    try std.testing.expectEqualStrings("abc", ft.text.items);
    try std.testing.expectEqual(@as(usize, 2), ft.entities.items.len);
    const bold_e = switch (ft.entities.items[0]) {
        .MessageEntityBold => |b| b,
        else => return error.WrongEntityType,
    };
    const italic_e = switch (ft.entities.items[1]) {
        .MessageEntityItalic => |b| b,
        else => return error.WrongEntityType,
    };
    try std.testing.expectEqual(@as(i32, 0), bold_e.offset);
    try std.testing.expectEqual(@as(i32, 1), bold_e.length);
    try std.testing.expectEqual(@as(i32, 2), italic_e.offset);
    try std.testing.expectEqual(@as(i32, 1), italic_e.length);
}
