//! Per-bucket versioning state and version snapshotting.
//!
//! Layout (per bucket):
//!   .simpaniz-versioning            — single-line state ("Enabled" / "Suspended")
//!   .simpaniz-versions/<key>/<vid>.data
//!   .simpaniz-versions/<key>/<vid>.meta.json   (caller-supplied JSON; opaque)
//!   .simpaniz-versions/<key>/<vid>.since       (lifecycle groundwork: noncurrent-since ns)
//!   .simpaniz-versions/<key>/null.delmarker    (suspended-state delete marker, sentinel vid "null")
//!   .simpaniz-meta/<key>.vid                   (current object's tracked version id, or "null")
//!
//! Only "Enabled" buckets snapshot prior versions on overwrite/delete.
//! Version IDs are 16 hex chars derived from time + random bytes, except the
//! sentinel "null" version id used for suspended/unversioned writes — S3's
//! null-version semantics: the current object then IS the null version, and
//! only one null version can exist at a time (a later PUT/DELETE while
//! Suspended replaces it in place rather than preserving it).

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

pub const State = enum { disabled, enabled, suspended };

pub fn getState(data_dir: Dir, bucket: []const u8) !State {
    var bd = data_dir.openDir(bucket, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.BucketNotFound,
        else => return error.Internal,
    };
    defer bd.close();
    var buf: [32]u8 = undefined;
    const slice = bd.readFile(paths.versioning_file, &buf) catch |e| switch (e) {
        error.FileNotFound => return .disabled,
        else => return error.Internal,
    };
    const trimmed = std.mem.trim(u8, slice, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "Enabled")) return .enabled;
    if (std.mem.eql(u8, trimmed, "Suspended")) return .suspended;
    return .disabled;
}

/// Set state from XML body. Accepts both `<Status>Enabled</Status>` and a bare
/// `Enabled` / `Suspended` string for ergonomics.
pub fn putState(data_dir: Dir, bucket: []const u8, body: []const u8) !void {
    var bd = data_dir.openDir(bucket, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.BucketNotFound,
        else => return error.Internal,
    };
    defer bd.close();

    const status = extractStatus(body) orelse return error.InvalidArgument;
    if (!std.mem.eql(u8, status, "Enabled") and !std.mem.eql(u8, status, "Suspended")) {
        return error.InvalidArgument;
    }
    try bd.writeFile(.{ .sub_path = paths.versioning_file, .data = status });
}

fn extractStatus(body: []const u8) ?[]const u8 {
    const open = "<Status>";
    const close = "</Status>";
    if (std.mem.indexOf(u8, body, open)) |s| {
        const start = s + open.len;
        const e = std.mem.indexOfPos(u8, body, start, close) orelse return null;
        return std.mem.trim(u8, body[start..e], " \t\r\n");
    }
    const t = std.mem.trim(u8, body, " \t\r\n");
    if (t.len == 0) return null;
    return t;
}

/// Generate a 16-hex-char version id (time-prefixed for sortability).
pub fn newVersionId(out: *[16]u8) void {
    const ts: u64 = @bitCast(std.time.milliTimestamp());
    var rand_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var raw: [8]u8 = undefined;
    // Pack time (high 32 bits) + 4 random bytes (low 32) for sortability + uniqueness.
    std.mem.writeInt(u32, raw[0..4], @truncate(ts), .big);
    @memcpy(raw[4..8], rand_bytes[0..4]);
    const hex = "0123456789abcdef";
    for (raw, 0..) |b, i| {
        out[i * 2] = hex[(b >> 4) & 0xF];
        out[i * 2 + 1] = hex[b & 0xF];
    }
}

/// Snapshot the current data + meta into the versions tree under `vid_hint`
/// (when it's a real 16-hex vid — i.e. the outgoing object's own tracked
/// version id) or a freshly minted vid otherwise (legacy/untracked objects,
/// or an outgoing "null" version, which is never itself preserved). Using
/// the outgoing object's own vid as the archive slot id is required for
/// continuity: `x-amz-version-id` returned on a PUT must remain resolvable
/// via `?versionId=` after the object is later overwritten.
/// `key` may contain "/" — translated to nested directories.
/// Returns the version id (caller owns the buffer).
pub fn snapshotCurrent(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
    vid_hint: ?[]const u8,
) !?[16]u8 {
    // No-op if the object doesn't actually exist.
    bd.access(key, .{}) catch return null;

    var vid: [16]u8 = undefined;
    if (vid_hint) |h| {
        if (h.len == 16) {
            @memcpy(&vid, h);
        } else {
            newVersionId(&vid);
        }
    } else {
        newVersionId(&vid);
    }

    const ver_subdir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.versions_dir, key });
    defer allocator.free(ver_subdir);
    try bd.makePath(ver_subdir);

    const data_path = try std.fmt.allocPrint(allocator, "{s}/{s}.data", .{ ver_subdir, vid });
    defer allocator.free(data_path);
    try bd.copyFile(key, bd, data_path, .{});

    const cur_meta = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, key });
    defer allocator.free(cur_meta);
    const ver_meta = try std.fmt.allocPrint(allocator, "{s}/{s}.meta.json", .{ ver_subdir, vid });
    defer allocator.free(ver_meta);
    bd.copyFile(cur_meta, bd, ver_meta, .{}) catch {};

    // Lifecycle groundwork: record the instant this version became
    // noncurrent, so a future noncurrent-expiration sweep can consume it.
    const since_path = try std.fmt.allocPrint(allocator, "{s}/{s}.since", .{ ver_subdir, vid });
    defer allocator.free(since_path);
    var since_buf: [40]u8 = undefined;
    const since_s = std.fmt.bufPrint(&since_buf, "{d}", .{std.time.nanoTimestamp()}) catch "0";
    bd.writeFile(.{ .sub_path = since_path, .data = since_s }) catch {};

    return vid;
}

fn vidSidecarPath(allocator: Allocator, key: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}.vid", .{ paths.meta_dir, key });
}

/// The current object's tracked version id: "null" for objects written while
/// versioning was disabled/suspended, or a 16-hex vid for objects written
/// while Enabled. Defaults to "null" when no sidecar exists (legacy objects,
/// or keys that predate this tracking). Caller frees.
pub fn currentVersionId(bd: Dir, allocator: Allocator, key: []const u8) ![]u8 {
    const p = try vidSidecarPath(allocator, key);
    defer allocator.free(p);
    var buf: [32]u8 = undefined;
    const slice = bd.readFile(p, &buf) catch return allocator.dupe(u8, "null");
    const trimmed = std.mem.trim(u8, slice, " \t\r\n");
    return allocator.dupe(u8, if (trimmed.len == 0) "null" else trimmed);
}

/// Record the version id the current object now carries. Called right after
/// a successful PUT.
pub fn setCurrentVersionId(bd: Dir, allocator: Allocator, key: []const u8, vid: []const u8) !void {
    const p = try vidSidecarPath(allocator, key);
    defer allocator.free(p);
    if (std.fs.path.dirname(p)) |parent| bd.makePath(parent) catch {};
    bd.writeFile(.{ .sub_path = p, .data = vid }) catch return error.Internal;
}

/// Drop the current-version-id sidecar (the current object itself was just
/// permanently removed).
pub fn deleteCurrentVersionIdSidecar(bd: Dir, allocator: Allocator, key: []const u8) void {
    const p = vidSidecarPath(allocator, key) catch return;
    defer allocator.free(p);
    bd.deleteFile(p) catch {};
}

/// Write (or replace) the sentinel "null" delete marker for `key`. Suspended-
/// state DELETE semantics: only one null-version delete marker may exist at
/// a time, so re-deleting simply overwrites it in place.
pub fn setNullDeleteMarker(bd: Dir, allocator: Allocator, key: []const u8) !void {
    const ver_subdir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.versions_dir, key });
    defer allocator.free(ver_subdir);
    bd.makePath(ver_subdir) catch return error.Internal;
    const dm_p = try std.fmt.allocPrint(allocator, "{s}/null.delmarker", .{ver_subdir});
    defer allocator.free(dm_p);
    bd.writeFile(.{ .sub_path = dm_p, .data = "" }) catch return error.Internal;
}

/// Open a versioned object's data file. Returns null if not present.
pub fn openVersionData(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
    version_id: []const u8,
) !?std.fs.File {
    if (version_id.len != 16) return error.InvalidArgument;
    const p = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.data", .{ paths.versions_dir, key, version_id });
    defer allocator.free(p);
    return bd.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => null,
        else => error.Internal,
    };
}

/// Delete a specific version.
pub fn deleteVersion(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
    version_id: []const u8,
) !void {
    if (version_id.len != 16) return error.InvalidArgument;
    const data_p = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.data", .{ paths.versions_dir, key, version_id });
    defer allocator.free(data_p);
    const meta_p = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.meta.json", .{ paths.versions_dir, key, version_id });
    defer allocator.free(meta_p);
    const dm_p = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.delmarker", .{ paths.versions_dir, key, version_id });
    defer allocator.free(dm_p);
    bd.deleteFile(data_p) catch {};
    bd.deleteFile(meta_p) catch {};
    bd.deleteFile(dm_p) catch {};
}

/// Read the JSON metadata for a specific version. Caller frees.
pub fn readVersionMeta(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
    version_id: []const u8,
) !?[]u8 {
    if (version_id.len != 16) return error.InvalidArgument;
    const p = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.meta.json", .{ paths.versions_dir, key, version_id });
    defer allocator.free(p);
    const f = bd.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return error.Internal,
    };
    defer f.close();
    const stat = f.stat() catch return error.Internal;
    const buf = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(buf);
    _ = f.readAll(buf) catch return error.Internal;
    return buf;
}

/// Append a delete-marker sentinel for `key` and return the new version id.
/// The marker is an empty file at `.simpaniz-versions/<key>/<vid>.delmarker`.
pub fn addDeleteMarker(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
) ![16]u8 {
    var vid: [16]u8 = undefined;
    newVersionId(&vid);
    const ver_subdir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.versions_dir, key });
    defer allocator.free(ver_subdir);
    bd.makePath(ver_subdir) catch return error.Internal;
    const dm_p = try std.fmt.allocPrint(allocator, "{s}/{s}.delmarker", .{ ver_subdir, vid });
    defer allocator.free(dm_p);
    bd.writeFile(.{ .sub_path = dm_p, .data = "" }) catch return error.Internal;
    return vid;
}

pub const VersionEntry = struct {
    key: []u8, // owned
    version_id: []u8, // owned; 16 hex chars, or "null" for the current null version
    is_delete_marker: bool,
    is_latest: bool,
    size: u64,
    mtime_ns: i128,
    etag: []u8, // owned (may be empty for delete markers)
    noncurrent_since_ns: i128 = 0, // 0 when unknown/not-yet-noncurrent (lifecycle groundwork)
    // Internal sort hint: true for the live object entry (section 2 below).
    // A snapshot is always taken strictly before the write that supersedes
    // it, but filesystem mtime resolution (coarse on some platforms) can't
    // be trusted to order the two deterministically when they land in the
    // same tick — so IsLatest/ordering pins the live entry first explicitly
    // rather than relying on a raw mtime comparison.
    is_live: bool = false,
};

fn etagFromMetaJson(dir: Dir, meta_rel_path: []const u8) ?[]const u8 {
    var mb: [1024]u8 = undefined;
    const slice = dir.readFile(meta_rel_path, &mb) catch return null;
    const i = std.mem.indexOf(u8, slice, "\"etag\":\"") orelse return null;
    const s = i + 8;
    const e2 = std.mem.indexOfPos(u8, slice, s, "\"") orelse return null;
    return slice[s..e2];
}

/// Walk `.simpaniz-versions/` (snapshots + delete markers) *and* the live
/// object tree, returning one VersionEntry per snapshot/delete-marker/current
/// object. Sorted by key ASC, mtime DESC (newest first per key); the current
/// live object — when present — is always newest for its key since a
/// snapshot is always taken strictly before the overwrite that produced it.
/// Caller frees.
pub fn listVersions(
    bd: Dir,
    allocator: Allocator,
    prefix: []const u8,
) ![]VersionEntry {
    var out = std.ArrayList(VersionEntry){};
    errdefer {
        for (out.items) |e| {
            allocator.free(e.key);
            allocator.free(e.etag);
            allocator.free(e.version_id);
        }
        out.deinit(allocator);
    }

    // 1) Snapshotted versions + delete markers under .simpaniz-versions/.
    var have_ver_root = true;
    var ver_root: Dir = bd.openDir(paths.versions_dir, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => blk: {
            have_ver_root = false;
            break :blk undefined;
        },
        else => return error.Internal,
    };
    defer if (have_ver_root) ver_root.close();

    if (have_ver_root) {
        var walker = ver_root.walk(allocator) catch return error.OutOfMemory;
        defer walker.deinit();
        while (walker.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            // path is `<key…>/<vid>.<ext>` (Dir.Walker joins with the
            // platform separator, so accept both '/' and '\' here).
            const path = entry.path;
            const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse continue;
            const slash = std.mem.lastIndexOfAny(u8, path[0..dot], "/\\") orelse continue;
            const key = path[0..slash];
            const vid_str = path[slash + 1 .. dot];
            const ext = path[dot + 1 ..];
            const is_null_vid = std.mem.eql(u8, vid_str, "null");
            if (vid_str.len != 16 and !is_null_vid) continue;

            if (prefix.len > 0 and !std.mem.startsWith(u8, key, prefix)) continue;

            var is_dm = false;
            if (std.mem.eql(u8, ext, "delmarker")) {
                is_dm = true;
            } else if (std.mem.eql(u8, ext, "since")) {
                continue; // read alongside its .data sibling below
            } else if (!std.mem.eql(u8, ext, "data")) {
                continue;
            }

            const stat = entry.dir.statFile(entry.basename) catch continue;

            const key_norm = try allocator.dupe(u8, key);
            for (key_norm) |*c| if (c.* == '\\') {
                c.* = '/';
            };

            const vid_owned = try allocator.dupe(u8, vid_str);

            var etag: []u8 = try allocator.dupe(u8, "");
            var noncurrent_since_ns: i128 = 0;
            if (!is_dm) {
                var meta_buf: [512]u8 = undefined;
                if (std.fmt.bufPrint(&meta_buf, "{s}/{s}.meta.json", .{ key_norm, vid_str })) |mp| {
                    if (etagFromMetaJson(ver_root, mp)) |et| {
                        allocator.free(etag);
                        etag = try allocator.dupe(u8, et);
                    }
                } else |_| {}

                var since_buf: [512]u8 = undefined;
                if (std.fmt.bufPrint(&since_buf, "{s}/{s}.since", .{ key_norm, vid_str })) |sp| {
                    var sb: [40]u8 = undefined;
                    if (ver_root.readFile(sp, &sb)) |slice| {
                        noncurrent_since_ns = std.fmt.parseInt(i128, std.mem.trim(u8, slice, " \t\r\n"), 10) catch 0;
                    } else |_| {}
                } else |_| {}
            }

            try out.append(allocator, .{
                .key = key_norm,
                .version_id = vid_owned,
                .is_delete_marker = is_dm,
                .is_latest = false,
                .size = if (is_dm) 0 else stat.size,
                .mtime_ns = stat.mtime,
                .etag = etag,
                .noncurrent_since_ns = noncurrent_since_ns,
            });
        }
    }

    // 2) The current (live) object per key.
    {
        var walker = bd.walk(allocator) catch return error.OutOfMemory;
        defer walker.deinit();
        while (walker.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.startsWith(u8, entry.path, paths.reserved_prefix)) continue;

            const key_norm = try allocator.dupe(u8, entry.path);
            for (key_norm) |*c| if (c.* == '\\') {
                c.* = '/';
            };

            if (prefix.len > 0 and !std.mem.startsWith(u8, key_norm, prefix)) {
                allocator.free(key_norm);
                continue;
            }

            const stat = entry.dir.statFile(entry.basename) catch {
                allocator.free(key_norm);
                continue;
            };

            const vid_owned = currentVersionId(bd, allocator, key_norm) catch try allocator.dupe(u8, "null");

            var etag: []u8 = try allocator.dupe(u8, "");
            var meta_buf: [512]u8 = undefined;
            if (std.fmt.bufPrint(&meta_buf, "{s}/{s}.json", .{ paths.meta_dir, key_norm })) |mp| {
                if (etagFromMetaJson(bd, mp)) |et| {
                    allocator.free(etag);
                    etag = try allocator.dupe(u8, et);
                }
            } else |_| {}

            try out.append(allocator, .{
                .key = key_norm,
                .version_id = vid_owned,
                .is_delete_marker = false,
                .is_latest = false,
                .size = stat.size,
                .mtime_ns = stat.mtime,
                .etag = etag,
                .noncurrent_since_ns = 0,
                .is_live = true,
            });
        }
    }

    // Sort: key ASC, then the live entry (if any) always first, then the
    // rest by mtime DESC. Filesystem mtime resolution can't be trusted to
    // order a snapshot against the write that superseded it when both land
    // in the same tick, so `is_live` — not raw mtime — decides precedence.
    std.mem.sort(VersionEntry, out.items, {}, struct {
        fn lt(_: void, a: VersionEntry, b: VersionEntry) bool {
            const cmp = std.mem.order(u8, a.key, b.key);
            if (cmp != .eq) return cmp == .lt;
            if (a.is_live != b.is_live) return a.is_live;
            return a.mtime_ns > b.mtime_ns;
        }
    }.lt);

    // Mark first per-key as latest.
    var prev: []const u8 = "";
    for (out.items) |*e| {
        if (!std.mem.eql(u8, e.key, prev)) {
            e.is_latest = true;
            prev = e.key;
        }
    }
    return out.toOwnedSlice(allocator);
}

test "versioning state round-trip" {
    const allocator = std.testing.allocator;
    _ = allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbucket");

    try std.testing.expectEqual(State.disabled, try getState(tmp.dir, "vbucket"));
    try putState(tmp.dir, "vbucket", "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
    try std.testing.expectEqual(State.enabled, try getState(tmp.dir, "vbucket"));
    try putState(tmp.dir, "vbucket", "Suspended");
    try std.testing.expectEqual(State.suspended, try getState(tmp.dir, "vbucket"));
}

test "snapshot writes versioned copy" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt");
    var bd = try tmp.dir.openDir("vbkt", .{});
    defer bd.close();
    try bd.writeFile(.{ .sub_path = "obj.txt", .data = "v1 body" });

    const vid = (try snapshotCurrent(bd, allocator, "obj.txt", null)).?;

    var f = (try openVersionData(bd, allocator, "obj.txt", &vid)).?;
    defer f.close();
    var buf: [16]u8 = undefined;
    const n = try f.read(&buf);
    try std.testing.expectEqualStrings("v1 body", buf[0..n]);

    try deleteVersion(bd, allocator, "obj.txt", &vid);
    try std.testing.expect((try openVersionData(bd, allocator, "obj.txt", &vid)) == null);
}

fn freeEntries(allocator: Allocator, entries: []VersionEntry) void {
    for (entries) |e| {
        allocator.free(e.key);
        allocator.free(e.etag);
        allocator.free(e.version_id);
    }
    allocator.free(entries);
}

test "listVersions: enabled state keeps prior versions, newest first, latest flagged once" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt1");
    var bd = try tmp.dir.openDir("vbkt1", .{ .iterate = true });
    defer bd.close();

    try putState(tmp.dir, "vbkt1", "Enabled");

    try bd.writeFile(.{ .sub_path = "k", .data = "v1" });
    var v1_vid: [16]u8 = undefined;
    newVersionId(&v1_vid);
    try setCurrentVersionId(bd, allocator, "k", &v1_vid);

    std.Thread.sleep(2 * std.time.ns_per_ms);

    // Overwrite while Enabled: snapshot the outgoing version first, under
    // its OWN tracked vid (continuity: the vid returned on its own PUT must
    // remain resolvable via ?versionId= after it's superseded).
    _ = (try snapshotCurrent(bd, allocator, "k", &v1_vid)).?;
    try bd.writeFile(.{ .sub_path = "k", .data = "v2 body" });
    var v2_vid: [16]u8 = undefined;
    newVersionId(&v2_vid);
    try setCurrentVersionId(bd, allocator, "k", &v2_vid);

    const entries = try listVersions(bd, allocator, "");
    defer freeEntries(allocator, entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expect(entries[0].is_latest);
    try std.testing.expect(!entries[1].is_latest);
    try std.testing.expectEqualStrings(&v2_vid, entries[0].version_id);
    try std.testing.expectEqualStrings(&v1_vid, entries[1].version_id);
    try std.testing.expect(!std.mem.eql(u8, entries[0].version_id, "null"));
    try std.testing.expect(!std.mem.eql(u8, entries[1].version_id, "null"));
}

test "suspended overwrite: enabled-era version preserved, then null replaces null in place" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt2");
    var bd = try tmp.dir.openDir("vbkt2", .{ .iterate = true });
    defer bd.close();

    try putState(tmp.dir, "vbkt2", "Enabled");

    // Enabled-era PUT: current carries a real (non-null) version id.
    try bd.writeFile(.{ .sub_path = "k", .data = "enabled-v1" });
    var real_vid: [16]u8 = undefined;
    newVersionId(&real_vid);
    try setCurrentVersionId(bd, allocator, "k", &real_vid);

    std.Thread.sleep(2 * std.time.ns_per_ms);
    try putState(tmp.dir, "vbkt2", "Suspended");

    // Suspended overwrite #1: current is non-null -> snapshot it aside, then
    // the new current becomes the null version.
    {
        const cur = try currentVersionId(bd, allocator, "k");
        defer allocator.free(cur);
        try std.testing.expect(!std.mem.eql(u8, cur, "null"));
    }
    _ = try snapshotCurrent(bd, allocator, "k", &real_vid);
    try bd.writeFile(.{ .sub_path = "k", .data = "suspended-v1" });
    try setCurrentVersionId(bd, allocator, "k", "null");

    // The enabled-era version is preserved and retrievable by its real vid.
    {
        var f = (try openVersionData(bd, allocator, "k", &real_vid)).?;
        defer f.close();
        var buf: [32]u8 = undefined;
        const n = try f.read(&buf);
        try std.testing.expectEqualStrings("enabled-v1", buf[0..n]);
    }

    {
        const cur = try currentVersionId(bd, allocator, "k");
        defer allocator.free(cur);
        try std.testing.expectEqualStrings("null", cur);
    }

    std.Thread.sleep(2 * std.time.ns_per_ms);

    // Suspended overwrite #2: current is already null -> replace in place,
    // no additional snapshot (nulls are never preserved).
    try bd.writeFile(.{ .sub_path = "k", .data = "suspended-v2" });
    try setCurrentVersionId(bd, allocator, "k", "null");

    const entries = try listVersions(bd, allocator, "");
    defer freeEntries(allocator, entries);
    // Exactly 2: the preserved enabled-era snapshot + the current null
    // version. The second suspended overwrite did not grow the version count.
    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "suspended delete: null delete marker replaces in place, no duplicates" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt3");
    var bd = try tmp.dir.openDir("vbkt3", .{ .iterate = true });
    defer bd.close();

    try putState(tmp.dir, "vbkt3", "Suspended");

    try bd.writeFile(.{ .sub_path = "k", .data = "null-v1" });
    try setCurrentVersionId(bd, allocator, "k", "null");

    try setNullDeleteMarker(bd, allocator, "k");
    bd.deleteFile("k") catch {};
    deleteCurrentVersionIdSidecar(bd, allocator, "k");

    {
        const entries = try listVersions(bd, allocator, "");
        defer freeEntries(allocator, entries);
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expect(entries[0].is_delete_marker);
        try std.testing.expectEqualStrings("null", entries[0].version_id);
    }

    // Re-PUT then delete again — the null marker is replaced, not duplicated.
    try bd.writeFile(.{ .sub_path = "k", .data = "null-v2" });
    try setCurrentVersionId(bd, allocator, "k", "null");
    try setNullDeleteMarker(bd, allocator, "k");
    bd.deleteFile("k") catch {};
    deleteCurrentVersionIdSidecar(bd, allocator, "k");

    {
        const entries = try listVersions(bd, allocator, "");
        defer freeEntries(allocator, entries);
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        try std.testing.expect(entries[0].is_delete_marker);
        try std.testing.expectEqualStrings("null", entries[0].version_id);
    }
}

test "currentVersionId defaults to null when untracked and round-trips real vids" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt4");
    var bd = try tmp.dir.openDir("vbkt4", .{});
    defer bd.close();

    try bd.writeFile(.{ .sub_path = "k", .data = "x" });

    // No sidecar written yet -> legacy/back-compat default "null".
    {
        const default_vid = try currentVersionId(bd, allocator, "k");
        defer allocator.free(default_vid);
        try std.testing.expectEqualStrings("null", default_vid);
    }

    var vid: [16]u8 = undefined;
    newVersionId(&vid);
    try setCurrentVersionId(bd, allocator, "k", &vid);
    {
        const tracked = try currentVersionId(bd, allocator, "k");
        defer allocator.free(tracked);
        try std.testing.expectEqualStrings(&vid, tracked);
    }
}

test "snapshotCurrent records noncurrent_since_ns, exposed via listVersions" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    try buckets.createBucket(tmp.dir, "vbkt5");
    var bd = try tmp.dir.openDir("vbkt5", .{ .iterate = true });
    defer bd.close();

    try bd.writeFile(.{ .sub_path = "k", .data = "v1" });
    const before = std.time.nanoTimestamp();
    _ = try snapshotCurrent(bd, allocator, "k", null);
    const after = std.time.nanoTimestamp();
    // Snapshot is a copy, not a move — overwrite the live object afterward,
    // matching real PUT/DELETE usage (snapshot precedes the mutation).
    try bd.writeFile(.{ .sub_path = "k", .data = "v2" });

    const entries = try listVersions(bd, allocator, "");
    defer freeEntries(allocator, entries);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    const snapshot = for (entries) |e| {
        if (!e.is_latest) break e;
    } else unreachable;
    try std.testing.expect(snapshot.noncurrent_since_ns >= before);
    try std.testing.expect(snapshot.noncurrent_since_ns <= after);
}
