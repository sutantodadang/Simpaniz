//! Per-bucket versioning state and version snapshotting.
//!
//! Layout (per bucket):
//!   .simpaniz-versioning            — single-line state ("Enabled" / "Suspended")
//!   .simpaniz-versions/<key>/<vid>.data
//!   .simpaniz-versions/<key>/<vid>.meta.json   (caller-supplied JSON; opaque)
//!
//! Only "Enabled" buckets snapshot prior versions on overwrite/delete.
//! Version IDs are 16 hex chars derived from time + random bytes.

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

/// Snapshot the current data + meta into the versions tree under a fresh vid.
/// `key` may contain "/" — translated to nested directories.
/// Returns the version id (caller owns the buffer).
pub fn snapshotCurrent(
    bd: Dir,
    allocator: Allocator,
    key: []const u8,
) !?[16]u8 {
    // No-op if the object doesn't actually exist.
    bd.access(key, .{}) catch return null;

    var vid: [16]u8 = undefined;
    newVersionId(&vid);

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

    return vid;
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
    version_id: [16]u8,
    is_delete_marker: bool,
    is_latest: bool,
    size: u64,
    mtime_ns: i128,
    etag: []u8, // owned (may be empty for delete markers)
};

/// Walk `.simpaniz-versions/` and return one VersionEntry per snapshot/delete
/// marker. Sorted by key ASC, mtime DESC (newest first per key). Caller frees.
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
        }
        out.deinit(allocator);
    }

    var ver_root = bd.openDir(paths.versions_dir, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return out.toOwnedSlice(allocator),
        else => return error.Internal,
    };
    defer ver_root.close();

    var walker = ver_root.walk(allocator) catch return error.OutOfMemory;
    defer walker.deinit();
    while (walker.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        // path is `<key…>/<vid>.<ext>`
        const path = entry.path;
        const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse continue;
        const slash = std.mem.lastIndexOfScalar(u8, path[0..dot], '/') orelse continue;
        const key = path[0..slash];
        const vid_str = path[slash + 1 .. dot];
        const ext = path[dot + 1 ..];
        if (vid_str.len != 16) continue;

        if (prefix.len > 0 and !std.mem.startsWith(u8, key, prefix)) continue;

        var is_dm = false;
        if (std.mem.eql(u8, ext, "delmarker")) {
            is_dm = true;
        } else if (!std.mem.eql(u8, ext, "data")) {
            continue;
        }

        const stat = entry.dir.statFile(entry.basename) catch continue;

        const key_norm = try allocator.dupe(u8, key);
        for (key_norm) |*c| if (c.* == '\\') {
            c.* = '/';
        };

        var vid_arr: [16]u8 = undefined;
        @memcpy(&vid_arr, vid_str);

        var etag: []u8 = try allocator.dupe(u8, "");
        if (!is_dm) {
            // Try to read companion meta for ETag.
            var meta_buf: [512]u8 = undefined;
            const meta_p = std.fmt.bufPrint(&meta_buf, "{s}/{s}.meta.json", .{ key, vid_str }) catch null;
            if (meta_p) |mp| {
                var mb: [1024]u8 = undefined;
                if (ver_root.readFile(mp, &mb)) |slice| {
                    if (std.mem.indexOf(u8, slice, "\"etag\":\"")) |i| {
                        const s = i + 8;
                        if (std.mem.indexOfPos(u8, slice, s, "\"")) |e2| {
                            allocator.free(etag);
                            etag = try allocator.dupe(u8, slice[s..e2]);
                        }
                    }
                } else |_| {}
            }
        }

        try out.append(allocator, .{
            .key = key_norm,
            .version_id = vid_arr,
            .is_delete_marker = is_dm,
            .is_latest = false,
            .size = if (is_dm) 0 else stat.size,
            .mtime_ns = stat.mtime,
            .etag = etag,
        });
    }

    // Sort: key ASC, mtime DESC.
    std.mem.sort(VersionEntry, out.items, {}, struct {
        fn lt(_: void, a: VersionEntry, b: VersionEntry) bool {
            const cmp = std.mem.order(u8, a.key, b.key);
            if (cmp != .eq) return cmp == .lt;
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

    const vid = (try snapshotCurrent(bd, allocator, "obj.txt")).?;

    var f = (try openVersionData(bd, allocator, "obj.txt", &vid)).?;
    defer f.close();
    var buf: [16]u8 = undefined;
    const n = try f.read(&buf);
    try std.testing.expectEqualStrings("v1 body", buf[0..n]);

    try deleteVersion(bd, allocator, "obj.txt", &vid);
    try std.testing.expect((try openVersionData(bd, allocator, "obj.txt", &vid)) == null);
}
