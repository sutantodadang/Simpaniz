//! Bucket Lifecycle Configuration storage + sweeper.
//!
//! Wire format (S3-compatible XML):
//!   <LifecycleConfiguration>
//!     <Rule>
//!       <ID>...</ID>
//!       <Status>Enabled|Disabled</Status>
//!       <Filter><Prefix>...</Prefix></Filter>
//!       <Expiration><Days>N</Days></Expiration>
//!       <Transition><Days>N</Days><StorageClass>GLACIER</StorageClass></Transition>
//!       <NoncurrentVersionExpiration><NoncurrentDays>N</NoncurrentDays></NoncurrentVersionExpiration>
//!     </Rule>
//!   </LifecycleConfiguration>
//!
//! `<Filter>` may hold a bare `<Prefix>`, a bare `<Tag><Key>/<Value></Tag>`,
//! or both wrapped in `<And>...</And>`. Only a single tag filter is
//! supported (no multi-tag AND).
//!
//! On-disk format: `.simpaniz-lifecycle.xml` per bucket. We keep both the
//! parsed rules and the original XML so GET returns byte-identical XML.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const paths = @import("paths.zig");
const types = @import("types.zig");
const internal = @import("internal.zig");
const versioning = @import("versioning.zig");
const index_mod = @import("../index.zig");
const tiering_mod = @import("../tiering.zig");

pub const Rule = struct {
    id: []const u8 = "",
    prefix: []const u8 = "",
    expiration_days: u32 = 0,
    /// <NoncurrentVersionExpiration><NoncurrentDays>
    noncurrent_expiration_days: u32 = 0,
    /// <Transition><Days>
    transition_days: u32 = 0,
    /// <Transition><StorageClass> (e.g. GLACIER/COLD)
    transition_storage_class: []const u8 = "",
    /// <Filter><Tag><Key> (or inside <And>). Empty means no tag filter.
    tag_key: []const u8 = "",
    tag_value: []const u8 = "",
    enabled: bool = true,
};

pub const Config = struct {
    rules: []Rule,

    pub fn deinit(self: *Config, allocator: Allocator) void {
        for (self.rules) |r| {
            allocator.free(r.id);
            allocator.free(r.prefix);
            allocator.free(r.transition_storage_class);
            allocator.free(r.tag_key);
            allocator.free(r.tag_value);
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
            allocator.free(r.transition_storage_class);
            allocator.free(r.tag_key);
            allocator.free(r.tag_value);
        }
        rules.deinit(allocator);
    }

    var i: usize = 0;
    while (findTag(xml_body, "<Rule>", i)) |start| {
        const close = findTag(xml_body, "</Rule>", start) orelse break;
        const block = xml_body[start..close];

        const id = extractText(block, "ID") orelse "";
        const status = extractText(block, "Status") orelse "Enabled";

        // Filter: Prefix + (optional) single Tag, possibly wrapped in <And>.
        const filter_block = extractBlock(block, "<Filter>", "</Filter>") orelse block;
        const prefix = extractText(filter_block, "Prefix") orelse "";
        const tag_key = extractText(filter_block, "Key") orelse "";
        const tag_value = extractText(filter_block, "Value") orelse "";

        // Expiration and Transition each have their own <Days> — scope the
        // extraction to each sub-block so they don't get confused with each
        // other (or with NoncurrentVersionExpiration's NoncurrentDays).
        const expiration_block = extractBlock(block, "<Expiration>", "</Expiration>");
        const expiration_days = if (expiration_block) |eb| parseDaysTag(eb) else 0;

        const transition_block = extractBlock(block, "<Transition>", "</Transition>");
        var transition_days: u32 = 0;
        var transition_storage_class: []const u8 = "";
        if (transition_block) |tb| {
            transition_days = parseDaysTag(tb);
            transition_storage_class = extractText(tb, "StorageClass") orelse "";
        }

        const noncurrent_block = extractBlock(block, "<NoncurrentVersionExpiration>", "</NoncurrentVersionExpiration>");
        var noncurrent_expiration_days: u32 = 0;
        if (noncurrent_block) |nb| {
            const days_str = extractText(nb, "NoncurrentDays") orelse "0";
            noncurrent_expiration_days = std.fmt.parseInt(u32, std.mem.trim(u8, days_str, " \t\r\n"), 10) catch 0;
        }

        try rules.append(allocator, .{
            .id = try allocator.dupe(u8, std.mem.trim(u8, id, " \t\r\n")),
            .prefix = try allocator.dupe(u8, std.mem.trim(u8, prefix, " \t\r\n")),
            .expiration_days = expiration_days,
            .noncurrent_expiration_days = noncurrent_expiration_days,
            .transition_days = transition_days,
            .transition_storage_class = try allocator.dupe(u8, std.mem.trim(u8, transition_storage_class, " \t\r\n")),
            .tag_key = try allocator.dupe(u8, std.mem.trim(u8, tag_key, " \t\r\n")),
            .tag_value = try allocator.dupe(u8, std.mem.trim(u8, tag_value, " \t\r\n")),
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

/// Return the slice strictly between the first `open`..`close` tag pair
/// (tags excluded), or null if either tag is missing.
fn extractBlock(haystack: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    const s = std.mem.indexOf(u8, haystack, open) orelse return null;
    const e = std.mem.indexOfPos(u8, haystack, s + open.len, close) orelse return null;
    return haystack[s + open.len .. e];
}

fn parseDaysTag(block: []const u8) u32 {
    const s = extractText(block, "Days") orelse return 0;
    return std.fmt.parseInt(u32, std.mem.trim(u8, s, " \t\r\n"), 10) catch 0;
}

/// True if the object's stored tag set (`.simpaniz-tags/<key>.xml`) contains
/// a `<Tag>` whose Key/Value match exactly.
fn objectHasTag(bd: Dir, allocator: Allocator, key: []const u8, tag_key: []const u8, tag_value: []const u8) bool {
    const tags_path = std.fmt.allocPrint(allocator, "{s}/{s}.xml", .{ paths.tags_dir, key }) catch return false;
    defer allocator.free(tags_path);
    var buf: [64 * 1024]u8 = undefined;
    const xml_body = bd.readFile(tags_path, &buf) catch return false;

    var i: usize = 0;
    while (findTag(xml_body, "<Tag>", i)) |start| {
        const close = findTag(xml_body, "</Tag>", start) orelse break;
        const block = xml_body[start..close];
        const k = std.mem.trim(u8, extractText(block, "Key") orelse "", " \t\r\n");
        const v = std.mem.trim(u8, extractText(block, "Value") orelse "", " \t\r\n");
        if (std.mem.eql(u8, k, tag_key) and std.mem.eql(u8, v, tag_value)) return true;
        i = close + "</Tag>".len;
    }
    return false;
}

fn ruleMatches(bd: Dir, allocator: Allocator, rule: Rule, norm_key: []const u8) bool {
    if (!rule.enabled) return false;
    if (rule.prefix.len > 0 and !std.mem.startsWith(u8, norm_key, rule.prefix)) return false;
    if (rule.tag_key.len > 0 and !objectHasTag(bd, allocator, norm_key, rule.tag_key, rule.tag_value)) return false;
    return true;
}

pub const SweepStats = struct {
    expired: u64 = 0,
    scanned: u64 = 0,
    noncurrent_expired: u64 = 0,
    transitioned: u64 = 0,
};

/// Walk every bucket's lifecycle config, applying Expiration, Transition,
/// and NoncurrentVersionExpiration rules. When `index_mgr` is set, each
/// expired key is also removed from the persistent listing index
/// (single-node only — callers pass null in cluster mode). `tiering_ctx`
/// drives Transition rules; when null, Transition rules are skipped.
pub fn sweep(
    data_dir: Dir,
    allocator: Allocator,
    now_ns: i128,
    index_mgr: ?*index_mod.Manager,
    tiering_ctx: ?*tiering_mod.Tiering,
) !SweepStats {
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

        try sweepBucket(bd, entry.name, allocator, &cfg, now_ns, &stats, index_mgr, tiering_ctx);
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
    index_mgr: ?*index_mod.Manager,
    tiering_ctx: ?*tiering_mod.Tiering,
) !void {
    {
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

            var expired_this_object = false;
            for (cfg.rules) |rule| {
                if (rule.expiration_days == 0) continue;
                if (!ruleMatches(bd, allocator, rule, norm)) continue;

                const age_ns: i128 = now_ns - stat.mtime;
                const days_ns: i128 = @as(i128, rule.expiration_days) * std.time.ns_per_day;
                if (age_ns < days_ns) continue;

                // Expire: delete data + metadata sidecar.
                const meta_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, norm }) catch break;
                defer allocator.free(meta_path);
                bd.deleteFile(entry.path) catch break;
                bd.deleteFile(meta_path) catch {};
                if (index_mgr) |ix| ix.noteDelete(bucket_name, norm);
                std.log.info(
                    "lifecycle: expired bucket={s} key={s} rule={s} days={d}",
                    .{ bucket_name, norm, rule.id, rule.expiration_days },
                );
                stats.expired += 1;
                expired_this_object = true;
                break;
            }
            if (expired_this_object) continue;

            if (tiering_ctx) |tc| {
                for (cfg.rules) |rule| {
                    if (rule.transition_days == 0) continue;
                    if (!ruleMatches(bd, allocator, rule, norm)) continue;

                    const age_ns: i128 = now_ns - stat.mtime;
                    const days_ns: i128 = @as(i128, rule.transition_days) * std.time.ns_per_day;
                    if (age_ns < days_ns) continue;

                    const meta = internal.readMetadata(bd, allocator, norm) catch continue;
                    const already_tiered = meta.tiered;
                    freeReadMeta(allocator, meta);
                    if (already_tiered) continue; // idempotent

                    tc.transitionObject(bd, allocator, bucket_name, norm, rule.transition_storage_class) catch |e| {
                        std.log.warn("lifecycle: transition failed bucket={s} key={s}: {}", .{ bucket_name, norm, e });
                        continue;
                    };
                    std.log.info(
                        "lifecycle: transitioned bucket={s} key={s} rule={s} class={s}",
                        .{ bucket_name, norm, rule.id, rule.transition_storage_class },
                    );
                    stats.transitioned += 1;
                    break;
                }
            }
        }
    }

    // NoncurrentVersionExpiration: separate pass over the version tree.
    // ponytail: expires real noncurrent snapshots only — delete markers are
    // left alone until a rehydration/purge policy exists.
    var has_noncurrent_rule = false;
    for (cfg.rules) |rule| {
        if (rule.enabled and rule.noncurrent_expiration_days > 0) {
            has_noncurrent_rule = true;
            break;
        }
    }
    if (!has_noncurrent_rule) return;

    const entries = versioning.listVersions(bd, allocator, "") catch return;
    defer {
        for (entries) |e| {
            allocator.free(e.key);
            allocator.free(e.etag);
            allocator.free(e.version_id);
        }
        allocator.free(entries);
    }

    for (entries) |e| {
        if (e.is_latest) continue;
        if (e.is_delete_marker) continue;
        if (e.noncurrent_since_ns == 0) continue;

        for (cfg.rules) |rule| {
            if (rule.noncurrent_expiration_days == 0) continue;
            if (!ruleMatches(bd, allocator, rule, e.key)) continue;

            const age_ns: i128 = now_ns - e.noncurrent_since_ns;
            const days_ns: i128 = @as(i128, rule.noncurrent_expiration_days) * std.time.ns_per_day;
            if (age_ns < days_ns) continue;

            versioning.deleteVersion(bd, allocator, e.key, e.version_id) catch continue;
            std.log.info(
                "lifecycle: noncurrent-expired bucket={s} key={s} vid={s} rule={s}",
                .{ bucket_name, e.key, e.version_id, rule.id },
            );
            stats.noncurrent_expired += 1;
            break;
        }
    }
}

fn freeReadMeta(allocator: Allocator, meta: anytype) void {
    allocator.free(meta.content_type);
    allocator.free(meta.etag);
    allocator.free(meta.storage_class);
    if (meta.encryption) |enc| {
        allocator.free(enc.alg);
        allocator.free(enc.wrapped_dek_b64);
        allocator.free(enc.wrap_nonce_b64);
        allocator.free(enc.sse_c_key_md5);
        allocator.free(enc.kms_key_id);
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

test "parse rule with Expiration, Transition, NoncurrentVersionExpiration, and And(Prefix,Tag)" {
    const allocator = std.testing.allocator;
    const body =
        \\<LifecycleConfiguration>
        \\  <Rule>
        \\    <ID>full-rule</ID>
        \\    <Status>Enabled</Status>
        \\    <Filter>
        \\      <And>
        \\        <Prefix>archive/</Prefix>
        \\        <Tag><Key>env</Key><Value>prod</Value></Tag>
        \\      </And>
        \\    </Filter>
        \\    <Expiration><Days>30</Days></Expiration>
        \\    <Transition><Days>7</Days><StorageClass>GLACIER</StorageClass></Transition>
        \\    <NoncurrentVersionExpiration><NoncurrentDays>14</NoncurrentDays></NoncurrentVersionExpiration>
        \\  </Rule>
        \\</LifecycleConfiguration>
    ;
    var cfg = try parseXml(allocator, body);
    defer cfg.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), cfg.rules.len);
    const r = cfg.rules[0];
    try std.testing.expectEqualStrings("full-rule", r.id);
    try std.testing.expectEqualStrings("archive/", r.prefix);
    try std.testing.expectEqualStrings("env", r.tag_key);
    try std.testing.expectEqualStrings("prod", r.tag_value);
    // Expiration Days=30 must not be confused with Transition Days=7.
    try std.testing.expectEqual(@as(u32, 30), r.expiration_days);
    try std.testing.expectEqual(@as(u32, 7), r.transition_days);
    try std.testing.expectEqualStrings("GLACIER", r.transition_storage_class);
    try std.testing.expectEqual(@as(u32, 14), r.noncurrent_expiration_days);
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
    const stats = try sweep(tmp.dir, allocator, future, null, null);
    try std.testing.expect(stats.expired >= 1);

    // File is gone.
    var bd = try tmp.dir.openDir("lc-bucket", .{});
    defer bd.close();
    try std.testing.expectError(error.FileNotFound, bd.statFile("logs/old.txt"));
}

test "sweep with tag filter only expires the tagged object" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    const objects = @import("objects.zig");
    const tagging = @import("tagging.zig");
    try buckets.createBucket(tmp.dir, "tag-bucket");

    var fbs1 = std.Io.Reader.fixed("tagged");
    const m1 = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "tag-bucket",
        .key = "a.txt",
        .content_length = 6,
    }, &fbs1);
    allocator.free(m1.content_type);
    allocator.free(m1.etag);

    var fbs2 = std.Io.Reader.fixed("untagged");
    const m2 = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "tag-bucket",
        .key = "b.txt",
        .content_length = 8,
    }, &fbs2);
    allocator.free(m2.content_type);
    allocator.free(m2.etag);

    try tagging.putObjectTagging(tmp.dir, allocator, "tag-bucket", "a.txt",
        "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>",
    );

    try putBucketLifecycle(tmp.dir, allocator,
        "tag-bucket",
        "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status>" ++
            "<Filter><Tag><Key>env</Key><Value>prod</Value></Tag></Filter>" ++
            "<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    );

    const future = std.time.nanoTimestamp() + 2 * std.time.ns_per_day;
    const stats = try sweep(tmp.dir, allocator, future, null, null);
    try std.testing.expect(stats.expired >= 1);

    var bd = try tmp.dir.openDir("tag-bucket", .{});
    defer bd.close();
    try std.testing.expectError(error.FileNotFound, bd.statFile("a.txt"));
    _ = try bd.statFile("b.txt"); // untagged object survives
}

test "sweep expires noncurrent versions past NoncurrentVersionExpiration, live object intact" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "nv-bucket");
    var bd = try tmp.dir.openDir("nv-bucket", .{ .iterate = true });
    defer bd.close();

    try versioning.putState(tmp.dir, "nv-bucket", "Enabled");

    try bd.writeFile(.{ .sub_path = "k", .data = "v1" });
    var v1_vid: [16]u8 = undefined;
    versioning.newVersionId(&v1_vid);
    try versioning.setCurrentVersionId(bd, allocator, "k", &v1_vid);

    std.Thread.sleep(2 * std.time.ns_per_ms);
    _ = (try versioning.snapshotCurrent(bd, allocator, "k", &v1_vid)).?;
    try bd.writeFile(.{ .sub_path = "k", .data = "v2 body" });
    var v2_vid: [16]u8 = undefined;
    versioning.newVersionId(&v2_vid);
    try versioning.setCurrentVersionId(bd, allocator, "k", &v2_vid);

    std.Thread.sleep(2 * std.time.ns_per_ms);
    _ = (try versioning.snapshotCurrent(bd, allocator, "k", &v2_vid)).?;
    try bd.writeFile(.{ .sub_path = "k", .data = "v3 body!!" });
    var v3_vid: [16]u8 = undefined;
    versioning.newVersionId(&v3_vid);
    try versioning.setCurrentVersionId(bd, allocator, "k", &v3_vid);

    {
        const entries = try versioning.listVersions(bd, allocator, "");
        defer {
            for (entries) |e| {
                allocator.free(e.key);
                allocator.free(e.etag);
                allocator.free(e.version_id);
            }
            allocator.free(entries);
        }
        try std.testing.expectEqual(@as(usize, 3), entries.len); // 1 live + 2 noncurrent
    }

    try putBucketLifecycle(tmp.dir, allocator,
        "nv-bucket",
        "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status>" ++
            "<Filter><Prefix></Prefix></Filter>" ++
            "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>" ++
            "</Rule></LifecycleConfiguration>",
    );

    const future = std.time.nanoTimestamp() + 2 * std.time.ns_per_day;
    const stats = try sweep(tmp.dir, allocator, future, null, null);
    try std.testing.expectEqual(@as(u64, 2), stats.noncurrent_expired);

    const entries = try versioning.listVersions(bd, allocator, "");
    defer {
        for (entries) |e| {
            allocator.free(e.key);
            allocator.free(e.etag);
            allocator.free(e.version_id);
        }
        allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expect(entries[0].is_latest);
    try std.testing.expectEqualStrings(&v3_vid, entries[0].version_id);
}

test "sweep transitions object via local tiering; second sweep does not re-tier" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var cold_tmp = std.testing.tmpDir(.{ .iterate = true });
    defer cold_tmp.cleanup();

    const buckets = @import("buckets.zig");
    const objects = @import("objects.zig");
    try buckets.createBucket(tmp.dir, "trans-bucket");

    var fbs = std.Io.Reader.fixed("transition payload");
    const meta = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "trans-bucket",
        .key = "cold.bin",
        .content_length = 18,
    }, &fbs);
    allocator.free(meta.content_type);
    allocator.free(meta.etag);

    try putBucketLifecycle(tmp.dir, allocator,
        "trans-bucket",
        "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status>" ++
            "<Filter><Prefix></Prefix></Filter>" ++
            "<Transition><Days>1</Days><StorageClass>COLD</StorageClass></Transition>" ++
            "</Rule></LifecycleConfiguration>",
    );

    var tiering: tiering_mod.Tiering = .{ .mode = .local, .tier_root = cold_tmp.dir };

    const future = std.time.nanoTimestamp() + 2 * std.time.ns_per_day;
    const stats1 = try sweep(tmp.dir, allocator, future, null, &tiering);
    try std.testing.expectEqual(@as(u64, 1), stats1.transitioned);

    var bd = try tmp.dir.openDir("trans-bucket", .{});
    defer bd.close();
    const local_stat = try bd.statFile("cold.bin");
    try std.testing.expectEqual(@as(u64, 0), local_stat.size);

    const cold_bytes = try tiering.fetchCold(allocator, "trans-bucket", "cold.bin");
    defer allocator.free(cold_bytes);
    try std.testing.expectEqualStrings("transition payload", cold_bytes);

    // Idempotent: a second sweep sees the object already tiered and skips it.
    const stats2 = try sweep(tmp.dir, allocator, future, null, &tiering);
    try std.testing.expectEqual(@as(u64, 0), stats2.transitioned);
}
