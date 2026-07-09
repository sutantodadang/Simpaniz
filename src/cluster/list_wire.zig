//! Wire format for the internal `/_simpaniz/list` cluster-listing endpoint:
//! a small hand-rolled JSON encoding of `storage.types.ListPage` (mirrors
//! this codebase's existing convention — see `cluster/runtime.zig`'s
//! `ObjectMeta.toJson`/`fromJson` and `cluster/membership.zig`'s
//! `snapshotJson` — rather than pulling in `std.json.Stringify`).
//!
//! Deliberately depends on nothing cluster-internal (only `storage/types.zig`
//! + `xml.zig`) so both the serving side (`internal_handler.zig`, encode)
//! and the requesting side (`http_transport.zig`, decode) can import it
//! without risking an import cycle.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../storage/types.zig");
const xml = @import("../xml.zig");

/// Appends `s` to `list`, JSON-escaping characters that would otherwise
/// break out of a JSON string literal. Object keys are arbitrary S3 key
/// bytes (may contain `"`, `\`, control chars) so this can't be skipped the
/// way the rest of this codebase's hand-rolled JSON does for
/// known-constrained fields (hex etags, enum-ish strings, etc).
fn jsonEscapeInto(list: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            0x00...0x1f => {
                var buf: [6]u8 = undefined;
                const esc = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
                try list.appendSlice(allocator, esc);
            },
            else => try list.append(allocator, c),
        }
    }
}

/// Encode a `ListPage` (as returned by `list_index.Index.list`, i.e. with
/// `delimiter=""` so `common_prefixes` is always empty) into the JSON body
/// served by `/_simpaniz/list`.
pub fn encodeListPage(allocator: Allocator, page: types.ListPage) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"objects\":[");
    for (page.objects, 0..) |o, i| {
        if (i > 0) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "{\"key\":\"");
        try jsonEscapeInto(&buf, allocator, o.key);
        try buf.appendSlice(allocator, "\",\"last_modified\":\"");
        try jsonEscapeInto(&buf, allocator, o.last_modified);
        try buf.appendSlice(allocator, "\",\"etag\":\"");
        try jsonEscapeInto(&buf, allocator, o.etag);
        const size_str = try std.fmt.allocPrint(allocator, "\",\"size\":{d}}}", .{o.size});
        defer allocator.free(size_str);
        try buf.appendSlice(allocator, size_str);
    }
    try buf.appendSlice(allocator, "],\"is_truncated\":");
    try buf.appendSlice(allocator, if (page.is_truncated) "true" else "false");
    try buf.appendSlice(allocator, ",\"next_continuation_token\":\"");
    try jsonEscapeInto(&buf, allocator, page.next_continuation_token);
    try buf.appendSlice(allocator, "\"}");
    return buf.toOwnedSlice(allocator);
}

/// Decode a JSON body produced by `encodeListPage` back into a `ListPage`.
/// All returned strings/slices are freshly allocated (safe to outlive the
/// `json` input and the `std.json` parse arena, which is freed before
/// return).
pub fn decodeListPage(allocator: Allocator, json: []const u8) !types.ListPage {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.BadResponse;
    const obj = parsed.value.object;

    const objs_v = obj.get("objects") orelse return error.BadResponse;
    if (objs_v != .array) return error.BadResponse;
    const objects = try allocator.alloc(xml.ObjectInfo, objs_v.array.items.len);
    errdefer allocator.free(objects);
    for (objs_v.array.items, 0..) |item, i| {
        if (item != .object) return error.BadResponse;
        const io = item.object;
        const key_v = io.get("key") orelse return error.BadResponse;
        const lm_v = io.get("last_modified") orelse return error.BadResponse;
        const et_v = io.get("etag") orelse return error.BadResponse;
        const sz_v = io.get("size") orelse return error.BadResponse;
        if (key_v != .string or lm_v != .string or et_v != .string or sz_v != .integer) return error.BadResponse;
        objects[i] = .{
            .key = try allocator.dupe(u8, key_v.string),
            .last_modified = try allocator.dupe(u8, lm_v.string),
            .etag = try allocator.dupe(u8, et_v.string),
            .size = @intCast(sz_v.integer),
        };
    }

    const trunc_v = obj.get("is_truncated") orelse return error.BadResponse;
    if (trunc_v != .bool) return error.BadResponse;
    const nct_v = obj.get("next_continuation_token") orelse return error.BadResponse;
    if (nct_v != .string) return error.BadResponse;

    return .{
        .objects = objects,
        .common_prefixes = &.{},
        .is_truncated = trunc_v.bool,
        .next_continuation_token = try allocator.dupe(u8, nct_v.string),
    };
}

// ── Tests ───────────────────────────────────────────────────────────────────

const index_mod = @import("../index.zig");

test "encodeListPage/decodeListPage round-trip incl. keys needing escaping" {
    const a = std.testing.allocator;
    var objs = [_]xml.ObjectInfo{
        .{ .key = "a\"b\\c", .last_modified = "2024-01-01T00:00:00.000Z", .etag = "\"abc123\"", .size = 42 },
        .{ .key = "plain", .last_modified = "2024-01-02T00:00:00.000Z", .etag = "\"def456\"", .size = 7 },
    };
    const page: types.ListPage = .{
        .objects = &objs,
        .common_prefixes = &.{},
        .is_truncated = true,
        .next_continuation_token = "next\"key",
    };

    const json = try encodeListPage(a, page);
    defer a.free(json);

    const decoded = try decodeListPage(a, json);
    defer index_mod.freePage(a, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.objects.len);
    try std.testing.expectEqualStrings("a\"b\\c", decoded.objects[0].key);
    try std.testing.expectEqualStrings("\"abc123\"", decoded.objects[0].etag);
    try std.testing.expectEqualStrings("plain", decoded.objects[1].key);
    try std.testing.expect(decoded.is_truncated);
    try std.testing.expectEqualStrings("next\"key", decoded.next_continuation_token);
}

test "encodeListPage/decodeListPage round-trip an empty page" {
    const a = std.testing.allocator;
    const page: types.ListPage = .{ .objects = &.{}, .common_prefixes = &.{}, .is_truncated = false, .next_continuation_token = "" };
    const json = try encodeListPage(a, page);
    defer a.free(json);
    const decoded = try decodeListPage(a, json);
    defer index_mod.freePage(a, decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.objects.len);
    try std.testing.expect(!decoded.is_truncated);
}
