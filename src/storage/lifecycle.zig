//! Bucket Lifecycle Configuration storage + sweeper.
//!
//! Wire format (S3-compatible XML):
//!   <LifecycleConfiguration>
//!     <Rule>
//!       <ID>...</ID>
//!       <Status>Enabled|Disabled</Status>
//!       <Filter><Prefix>...</Prefix></Filter>
//!       <Expiration><Days>N</Days></Expiration>
//!     </Rule>
//!   </LifecycleConfiguration>
//!
//! On-disk format: `.simpaniz-lifecycle.json` per bucket. We keep both the
//! parsed rules and the original XML so GET returns byte-identical XML.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const paths = @import("paths.zig");
const types = @import("types.zig");
const internal = @import("internal.zig");

pub const Rule = struct {
    id: []const u8 = "",
    prefix: []const u8 = "",
    expiration_days: u32 = 0,
    enabled: bool = true,
};

pub const Config = struct {
    rules: []Rule,

    pub fn deinit(self: *Config, allocator: Allocator) void {
        for (self.rules) |r| {
            allocator.free(r.id);
            allocator.free(r.prefix);
        }
        allocator.free(self.rules);
    }
};

pub fn putBucketLifecycle(
    data_dir: Dir,
    allocator: Allocator,
    bucket: []const u8,
    xml_body: []const u8,
) !void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();

    // Parse first so invalid XML is rejected before persisting.
    var cfg = try parseXml(allocator, xml_body);
    defer cfg.deinit(allocator);

    bd.writeFile(.{ .sub_path = paths.lifecycle_file, .data = xml_body }) catch return error.Internal;
}

pub fn getBucketLifecycle(
    data_dir: Dir,
    allocator: Allocator,
    bucket: []const u8,
) !?[]u8 {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    var buf: [64 * 1024]u8 = undefined;
    const xml_body = bd.readFile(paths.lifecycle_file, &buf) catch return null;
    return try allocator.dupe(u8, xml_body);
}

pub fn deleteBucketLifecycle(data_dir: Dir, bucket: []const u8) !void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.deleteFile(paths.lifecycle_file) catch {};
}

/// Parse lifecycle XML into rules. Tolerant of whitespace and missing fields.
pub fn parseXml(allocator: Allocator, xml_body: []const u8) !Config {
    var rules = std.ArrayList(Rule){};
    errdefer {
        for (rules.items) |r| {
            allocator.free(r.id);
            allocator.free(r.prefix);
        }
        rules.deinit(allocator);
    }

    var i: usize = 0;
    while (findTag(xml_body, "<Rule>", i)) |start| {
        const close = findTag(xml_body, "</Rule>", start) orelse break;
        const block = xml_body[start..close];

        const id = extractText(block, "ID") orelse "";
        const status = extractText(block, "Status") orelse "Enabled";
        const prefix = extractText(block, "Prefix") orelse "";
        const days_str = extractText(block, "Days") orelse "0";

        const days = std.fmt.parseInt(u32, std.mem.trim(u8, days_str, " \t\r\n"), 10) catch 0;

        try rules.append(allocator, .{
            .id = try allocator.dupe(u8, std.mem.trim(u8, id, " \t\r\n")),
            .prefix = try allocator.dupe(u8, std.mem.trim(u8, prefix, " \t\r\n")),
            .expiration_days = days,
            .enabled = std.mem.eql(u8, std.mem.trim(u8, status, " \t\r\n"), "Enabled"),
        });

        i = close + "</Rule>".len;
    }
    if (rules.items.len == 0) return error.InvalidArgument;

    return .{ .rules = try rules.toOwnedSlice(allocator) };
}

fn findTag(haystack: []const u8, needle: []const u8, from: usize) ?usize {
    return std.mem.indexOfPos(u8, haystack, from, needle);
}

fn extractText(block: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const s = std.mem.indexOf(u8, block, open) orelse return null;
    const e = std.mem.indexOfPos(u8, block, s + open.len, close) orelse return null;
    return block[s + open.len .. e];
}

pub const SweepStats = struct {
    expired: u64 = 0,
    scanned: u64 = 0,
};

/// Walk every bucket's lifecycle config and delete objects older than each
/// rule's `expiration_days` whose key starts with `prefix`.
pub fn sweep(data_dir: Dir, allocator: Allocator, now_ns: i128) !SweepStats {
    var stats: SweepStats = .{};
    var iter = data_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.startsWith(u8, entry.name, ".")) continue;

        var bd = data_dir.openDir(entry.name, .{ .iterate = true }) catch continue;
        defer bd.close();

        var buf: [64 * 1024]u8 = undefined;
        const xml_body = bd.readFile(paths.lifecycle_file, &buf) catch continue;
        var cfg = parseXml(allocator, xml_body) catch continue;
        defer cfg.deinit(allocator);

        try sweepBucket(bd, entry.name, allocator, &cfg, now_ns, &stats);
    }
    return stats;
}

fn sweepBucket(
    bd: Dir,
    bucket_name: []const u8,
    allocator: Allocator,
    cfg: *const Config,
    now_ns: i128,
    stats: *SweepStats,
) !void {
    var walker = try bd.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.path, paths.reserved_prefix)) continue;
        if (std.mem.indexOf(u8, entry.path, "/" ++ paths.reserved_prefix) != null) continue;
        if (std.mem.indexOf(u8, entry.path, "\\" ++ paths.reserved_prefix) != null) continue;
        stats.scanned += 1;

        // Normalise to forward slashes for prefix matching (Windows uses \\).
        const norm = try allocator.dupe(u8, entry.path);
        defer allocator.free(norm);
        for (norm) |*c| if (c.* == '\\') {
            c.* = '/';
        };

        const stat = bd.statFile(entry.path) catch continue;

        for (cfg.rules) |rule| {
            if (!rule.enabled) continue;
            if (rule.expiration_days == 0) continue;
            if (rule.prefix.len > 0 and !std.mem.startsWith(u8, norm, rule.prefix)) continue;

            const age_ns: i128 = now_ns - stat.mtime;
            const days_ns: i128 = @as(i128, rule.expiration_days) * std.time.ns_per_day;
            if (age_ns < days_ns) continue;

            // Expire: delete data + metadata sidecar.
            const meta_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, norm }) catch break;
            defer allocator.free(meta_path);
            bd.deleteFile(entry.path) catch break;
            bd.deleteFile(meta_path) catch {};
            std.log.info(
                "lifecycle: expired bucket={s} key={s} rule={s} days={d}",
                .{ bucket_name, norm, rule.id, rule.expiration_days },
            );
            stats.expired += 1;
            break;
        }
    }
}

test "parse minimal lifecycle xml" {
    const allocator = std.testing.allocator;
    const body =
        \\<LifecycleConfiguration>
        \\  <Rule>
        \\    <ID>logs-7d</ID>
        \\    <Status>Enabled</Status>
        \\    <Filter><Prefix>logs/</Prefix></Filter>
        \\    <Expiration><Days>7</Days></Expiration>
        \\  </Rule>
        \\</LifecycleConfiguration>
    ;
    var cfg = try parseXml(allocator, body);
    defer cfg.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), cfg.rules.len);
    try std.testing.expectEqualStrings("logs-7d", cfg.rules[0].id);
    try std.testing.expectEqualStrings("logs/", cfg.rules[0].prefix);
    try std.testing.expectEqual(@as(u32, 7), cfg.rules[0].expiration_days);
    try std.testing.expect(cfg.rules[0].enabled);
}

test "sweep expires old object" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    const objects = @import("objects.zig");
    try buckets.createBucket(tmp.dir, "lc-bucket");

    var fbs = std.Io.Reader.fixed("expire me");
    const meta = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "lc-bucket",
        .key = "logs/old.txt",
        .content_length = 9,
        .content_type = "text/plain",
    }, &fbs);
    allocator.free(meta.content_type);
    allocator.free(meta.etag);

    try putBucketLifecycle(tmp.dir, allocator,
        "lc-bucket",
        "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status>" ++
            "<Filter><Prefix>logs/</Prefix></Filter>" ++
            "<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    );

    // Pretend "now" is 2 days in the future.
    const future = std.time.nanoTimestamp() + 2 * std.time.ns_per_day;
    const stats = try sweep(tmp.dir, allocator, future);
    try std.testing.expect(stats.expired >= 1);

    // File is gone.
    var bd = try tmp.dir.openDir("lc-bucket", .{});
    defer bd.close();
    try std.testing.expectError(error.FileNotFound, bd.statFile("logs/old.txt"));
}
