const types = @import("types");
const unions = @import("unions");

pub fn callbackButton(text: []const u8, data: []const u8) unions.KeyboardButton {
    return .{ .KeyboardButtonCallback = .{ .text = text, .data = data } };
}

pub fn urlButton(text: []const u8, url: []const u8) unions.KeyboardButton {
    return .{ .KeyboardButtonUrl = .{ .text = text, .url = url } };
}

pub fn inlineRow(buttons: []unions.KeyboardButton) types.KeyboardButtonRow {
    return .{ .buttons = buttons };
}

pub fn inlineKeyboard(rows: []types.KeyboardButtonRow) unions.ReplyMarkup {
    return .{ .ReplyInlineMarkup = .{ .rows = rows } };
}
