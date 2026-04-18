//! Per-object retention + legal hold storage.
//!
//! Layout (per bucket):
//!   .simpaniz-lock/<key>.json   — { "mode": "GOVERNANCE"|"COMPLIANCE",
//!                                   "retain_until_ns": <i128> }
//!   .simpaniz-hold/<key>        — empty file ⇒ legal hold ON
//!
//! Semantics:
//! - DELETE is blocked if legal hold is on, OR retain_until > now.
//! - GOVERNANCE may be bypassed with header `x-amz-bypass-governance-retention: true`.
//! - COMPLIANCE cannot be bypassed.

const std = @import("std");
const Dir = std.fs.Dir;
const Allocator = std.mem.Allocator;
const paths = @import("paths.zig");

pub const Error = error{
    BucketNotFound,
    InvalidArgument,
    NotFound,
    Internal,
} || std.fs.File.OpenError || std.fs.File.WriteError || std.mem.Allocator.Error;

pub const Mode = enum { governance, compliance };

pub const Retention = struct {
    mode: Mode,
    retain_until_ns: i128,
};

fn lockPath(allocator: Allocator, key: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.lock_dir, key });
}

fn holdPath(allocator: Allocator, key: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.legalhold_dir, key });
}

fn ensureParentDir(bd: Dir, sub: []const u8) !void {
    if (std.mem.lastIndexOfScalar(u8, sub, '/')) |i| {
        try bd.makePath(sub[0..i]);
    } else {
        try bd.makePath(".");
    }
}

pub fn putRetention(bd: Dir, allocator: Allocator, key: []const u8, ret: Retention) !void {
    const p = try lockPath(allocator, key);
    defer allocator.free(p);
    try ensureParentDir(bd, p);
    const mode_str = switch (ret.mode) {
        .governance => "GOVERNANCE",
        .compliance => "COMPLIANCE",
    };
    var buf: [256]u8 = undefined;
    const json = try std.fmt.bufPrint(&buf, "{{\"mode\":\"{s}\",\"retain_until_ns\":{d}}}", .{ mode_str, ret.retain_until_ns });
    try bd.writeFile(.{ .sub_path = p, .data = json });
}

pub fn getRetention(bd: Dir, allocator: Allocator, key: []const u8) !?Retention {
    const p = try lockPath(allocator, key);
    defer allocator.free(p);
    var buf: [512]u8 = undefined;
    const slice = bd.readFile(p, &buf) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return error.Internal,
    };
    const mode = extractField(slice, "\"mode\":\"", "\"") orelse return error.Internal;
    const until = extractField(slice, "\"retain_until_ns\":", "}") orelse return error.Internal;
    const m: Mode = if (std.mem.eql(u8, mode, "COMPLIANCE")) .compliance else .governance;
    const u = std.fmt.parseInt(i128, std.mem.trim(u8, until, " \t"), 10) catch return error.Internal;
    return .{ .mode = m, .retain_until_ns = u };
}

fn extractField(s: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, s, open) orelse return null;
    const start = i + open.len;
    const e = std.mem.indexOfPos(u8, s, start, close) orelse return null;
    return s[start..e];
}

pub fn putLegalHold(bd: Dir, allocator: Allocator, key: []const u8, on: bool) !void {
    const p = try holdPath(allocator, key);
    defer allocator.free(p);
    if (on) {
        try ensureParentDir(bd, p);
        try bd.writeFile(.{ .sub_path = p, .data = "" });
    } else {
        bd.deleteFile(p) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return error.Internal,
        };
    }
}

pub fn legalHoldOn(bd: Dir, allocator: Allocator, key: []const u8) bool {
    const p = holdPath(allocator, key) catch return false;
    defer allocator.free(p);
    bd.access(p, .{}) catch return false;
    return true;
}

/// Returns `true` when the object cannot be deleted/overwritten right now.
/// `bypass_governance` lets GOVERNANCE-mode locks be ignored.
pub fn isProtected(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
    now_ns: i128,
    bypass_governance: bool,
) bool {
    if (legalHoldOn(bd, allocator, key)) return true;
    const ret = (getRetention(bd, allocator, key) catch null) orelse return false;
    if (ret.retain_until_ns <= now_ns) return false;
    return switch (ret.mode) {
        .compliance => true,
        .governance => !bypass_governance,
    };
}

test "retention round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "lbkt");
    var bd = try tmp.dir.openDir("lbkt", .{});
    defer bd.close();

    try putRetention(bd, allocator, "k", .{ .mode = .compliance, .retain_until_ns = 12345 });
    const r = (try getRetention(bd, allocator, "k")).?;
    try std.testing.expectEqual(Mode.compliance, r.mode);
    try std.testing.expectEqual(@as(i128, 12345), r.retain_until_ns);
}

test "legal hold + protected check" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "lbkt");
    var bd = try tmp.dir.openDir("lbkt", .{});
    defer bd.close();

    try std.testing.expect(!isProtected(bd, allocator, "k", 0, false));
    try putLegalHold(bd, allocator, "k", true);
    try std.testing.expect(isProtected(bd, allocator, "k", 0, true));
    try putLegalHold(bd, allocator, "k", false);
    try std.testing.expect(!isProtected(bd, allocator, "k", 0, false));

    try putRetention(bd, allocator, "k", .{ .mode = .governance, .retain_until_ns = 999_999_999_999 });
    try std.testing.expect(isProtected(bd, allocator, "k", 0, false));
    try std.testing.expect(!isProtected(bd, allocator, "k", 0, true));

    try putRetention(bd, allocator, "k", .{ .mode = .compliance, .retain_until_ns = 999_999_999_999 });
    try std.testing.expect(isProtected(bd, allocator, "k", 0, true));
}
