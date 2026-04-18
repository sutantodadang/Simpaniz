//! Bucket-level Object Lock configuration.
//!
//! Layout (per bucket):
//!   .simpaniz-lock-config.json — { "enabled": bool,
//!                                  "default_mode": "GOVERNANCE"|"COMPLIANCE",
//!                                  "default_days": <u32> }
//!
//! When enabled and a default mode/days is set, PutObject auto-applies a
//! per-object retention if the request didn't carry explicit retention
//! headers. PUT/DELETE protection rules in `object_lock.zig` then enforce
//! WORM semantics as before.

const std = @import("std");
const Dir = std.fs.Dir;
const Allocator = std.mem.Allocator;
const paths = @import("paths.zig");
const object_lock = @import("object_lock.zig");

pub const Error = error{
    BucketNotFound,
    InvalidArgument,
    Internal,
} || std.mem.Allocator.Error;

pub const Config = struct {
    enabled: bool = false,
    default_mode: ?object_lock.Mode = null,
    default_days: u32 = 0,
};

pub fn put(data_dir: Dir, allocator: Allocator, bucket: []const u8, body: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();

    const enabled_s = extractTag(body, "ObjectLockEnabled") orelse "Enabled";
    const enabled = std.mem.eql(u8, std.mem.trim(u8, enabled_s, " \t\r\n"), "Enabled");

    var cfg: Config = .{ .enabled = enabled };
    if (extractTag(body, "Mode")) |m| {
        const mt = std.mem.trim(u8, m, " \t\r\n");
        if (std.mem.eql(u8, mt, "COMPLIANCE")) cfg.default_mode = .compliance;
        if (std.mem.eql(u8, mt, "GOVERNANCE")) cfg.default_mode = .governance;
    }
    if (extractTag(body, "Days")) |d| {
        const dt = std.mem.trim(u8, d, " \t\r\n");
        cfg.default_days = std.fmt.parseInt(u32, dt, 10) catch 0;
    }

    const json = try std.fmt.allocPrint(allocator, "{{\"enabled\":{any},\"mode\":\"{s}\",\"days\":{d}}}", .{
        cfg.enabled,
        if (cfg.default_mode) |m| @tagName(m) else "",
        cfg.default_days,
    });
    defer allocator.free(json);
    bd.writeFile(.{ .sub_path = paths.lock_config_file, .data = json }) catch return error.Internal;
}

pub fn get(data_dir: Dir, allocator: Allocator, bucket: []const u8) Error!?Config {
    _ = allocator;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    var buf: [512]u8 = undefined;
    const slice = bd.readFile(paths.lock_config_file, &buf) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return error.Internal,
    };
    const enabled_s = extractField(slice, "\"enabled\":", ",") orelse return error.Internal;
    const mode_s = extractField(slice, "\"mode\":\"", "\"") orelse "";
    const days_s = extractField(slice, "\"days\":", "}") orelse "0";
    var cfg: Config = .{ .enabled = std.mem.eql(u8, std.mem.trim(u8, enabled_s, " \t"), "true") };
    if (std.mem.eql(u8, mode_s, "compliance")) cfg.default_mode = .compliance;
    if (std.mem.eql(u8, mode_s, "governance")) cfg.default_mode = .governance;
    cfg.default_days = std.fmt.parseInt(u32, std.mem.trim(u8, days_s, " \t"), 10) catch 0;
    return cfg;
}

pub fn buildXml(allocator: Allocator, cfg: Config) Allocator.Error![]u8 {
    if (cfg.default_mode) |m| {
        return std.fmt.allocPrint(allocator,
            "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" ++
                "<ObjectLockEnabled>{s}</ObjectLockEnabled>" ++
                "<Rule><DefaultRetention><Mode>{s}</Mode><Days>{d}</Days></DefaultRetention></Rule>" ++
                "</ObjectLockConfiguration>",
            .{
                if (cfg.enabled) "Enabled" else "Disabled",
                switch (m) {
                    .governance => "GOVERNANCE",
                    .compliance => "COMPLIANCE",
                },
                cfg.default_days,
            });
    }
    return std.fmt.allocPrint(allocator,
        "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" ++
            "<ObjectLockEnabled>{s}</ObjectLockEnabled>" ++
            "</ObjectLockConfiguration>",
        .{if (cfg.enabled) "Enabled" else "Disabled"});
}

fn extractTag(body: []const u8, tag: []const u8) ?[]const u8 {
    var ob: [64]u8 = undefined;
    var cb: [64]u8 = undefined;
    const o = std.fmt.bufPrint(&ob, "<{s}>", .{tag}) catch return null;
    const c = std.fmt.bufPrint(&cb, "</{s}>", .{tag}) catch return null;
    const i = std.mem.indexOf(u8, body, o) orelse return null;
    const s = i + o.len;
    const e = std.mem.indexOfPos(u8, body, s, c) orelse return null;
    return body[s..e];
}

fn extractField(s: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, s, open) orelse return null;
    const start = i + open.len;
    const e = std.mem.indexOfPos(u8, s, start, close) orelse return null;
    return s[start..e];
}

test "lock config round-trip" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "lcfg");

    try put(tmp.dir, a,
        "lcfg",
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>" ++
            "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>7</Days></DefaultRetention></Rule>" ++
            "</ObjectLockConfiguration>",
    );
    const cfg = (try get(tmp.dir, a, "lcfg")).?;
    try std.testing.expect(cfg.enabled);
    try std.testing.expectEqual(object_lock.Mode.compliance, cfg.default_mode.?);
    try std.testing.expectEqual(@as(u32, 7), cfg.default_days);

    const xml = try buildXml(a, cfg);
    defer a.free(xml);
    try std.testing.expect(std.mem.indexOf(u8, xml, "COMPLIANCE") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Days>7</Days>") != null);
}
