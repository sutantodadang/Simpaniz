//! On-disk shard + meta storage for the cluster subsystem.
//!
//! Used by:
//!   - The cluster runtime when an op targets the local node (no network
//!     hop — go straight to disk).
//!   - The internal `/_simpaniz/shards/...` HTTP handler when a peer
//!     pushes a shard at us.
//!
//! Layout under the server's data_dir:
//!   .simpaniz-shards/<bucket>/<key>/<idx>.shard
//!   .simpaniz-meta/<bucket>/<key>.meta
//!
//! The bucket name is unrestricted here (we trust the caller — auth has
//! already gated requests). The key is written verbatim; '/' is allowed
//! and creates subdirectories. Cluster ops never collide with the
//! standard S3 layout because everything lives under dot-prefixed
//! directories.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const shards_root = ".simpaniz-shards";
pub const meta_root = ".simpaniz-meta";

fn shardPath(buf: []u8, bucket: []const u8, key: []const u8, idx: u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/{s}/{d}.shard", .{ shards_root, bucket, key, idx });
}

fn metaPath(buf: []u8, bucket: []const u8, key: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/{s}.meta", .{ meta_root, bucket, key });
}

pub fn putShard(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, payload: []const u8) !void {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    if (std.fs.path.dirname(p)) |dir| try data_dir.makePath(dir);
    var f = try data_dir.createFile(p, .{ .truncate = true });
    defer f.close();
    try f.writeAll(payload);
}

pub fn getShard(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, allocator: Allocator) !?[]u8 {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    var f = data_dir.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer f.close();
    const stat = try f.stat();
    const buf = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buf);
    const n = try f.readAll(buf);
    if (n != stat.size) return error.ShortRead;
    return buf;
}

/// Append `payload` (one stripe's chunk) to shard file `<idx>.shard` at
/// logical stripe index `seq`. Validates that the file's current length is
/// exactly `seq * payload.len` before appending; a length of
/// `(seq + 1) * payload.len` is treated as an already-applied retry
/// (idempotent no-op). Any other length is `error.SeqMismatch`.
pub fn appendShardChunk(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, seq: u64, payload: []const u8) !void {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    if (std.fs.path.dirname(p)) |dir| try data_dir.makePath(dir);
    var f = try data_dir.createFile(p, .{ .truncate = false, .read = true });
    defer f.close();
    const stat = try f.stat();
    const expected_before = seq * payload.len;
    if (stat.size == expected_before) {
        try f.seekTo(expected_before);
        try f.writeAll(payload);
    } else if (stat.size == expected_before + payload.len) {
        return; // idempotent replay
    } else {
        return error.SeqMismatch;
    }
}

/// Read up to `buf.len` bytes starting at `offset` from shard file
/// `<idx>.shard`. Returns the number of bytes actually read.
/// `error.ShardMissing` if the file does not exist.
pub fn getShardRange(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, offset: u64, buf: []u8) !usize {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    var f = data_dir.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.ShardMissing,
        else => return e,
    };
    defer f.close();
    try f.seekTo(offset);
    return try f.readAll(buf);
}

/// Total byte length of shard file `<idx>.shard`. `error.ShardMissing` if
/// the file does not exist.
pub fn statShard(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8) !u64 {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    var f = data_dir.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => return error.ShardMissing,
        else => return e,
    };
    defer f.close();
    const stat = try f.stat();
    return stat.size;
}

pub fn deleteShard(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8) !void {
    var pb: [1024]u8 = undefined;
    const p = try shardPath(&pb, bucket, key, idx);
    data_dir.deleteFile(p) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
}

pub fn putMeta(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, payload: []const u8) !void {
    var pb: [1024]u8 = undefined;
    const p = try metaPath(&pb, bucket, key);
    if (std.fs.path.dirname(p)) |dir| try data_dir.makePath(dir);
    var f = try data_dir.createFile(p, .{ .truncate = true });
    defer f.close();
    try f.writeAll(payload);
}

pub fn getMeta(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8, allocator: Allocator) !?[]u8 {
    var pb: [1024]u8 = undefined;
    const p = try metaPath(&pb, bucket, key);
    var f = data_dir.openFile(p, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer f.close();
    const stat = try f.stat();
    const buf = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buf);
    const n = try f.readAll(buf);
    if (n != stat.size) return error.ShortRead;
    return buf;
}

pub fn deleteMeta(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8) !void {
    var pb: [1024]u8 = undefined;
    const p = try metaPath(&pb, bucket, key);
    data_dir.deleteFile(p) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
}

/// Find the shard index (if any) this node currently stores locally for
/// (bucket, key). A node holds at most one shard file per key under
/// rendezvous placement (each of the k+m shard indices maps to a distinct
/// node). Used by the rebalance sweep to find what to migrate.
pub fn localShardIndex(data_dir: std.fs.Dir, bucket: []const u8, key: []const u8) !?u8 {
    var pb: [1024]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&pb, "{s}/{s}/{s}", .{ shards_root, bucket, key });
    var dir = data_dir.openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".shard")) continue;
        const idx_str = entry.name[0 .. entry.name.len - ".shard".len];
        const idx = std.fmt.parseInt(u8, idx_str, 10) catch continue;
        return idx;
    }
    return null;
}

/// Walk every (bucket, key) for which this node has at least one local
/// shard or a local meta file. Used by the heal daemon.
pub fn forEachLocalKey(
    data_dir: std.fs.Dir,
    allocator: Allocator,
    visit_ctx: *anyopaque,
    visit: *const fn (ctx: *anyopaque, bucket: []const u8, key: []const u8) anyerror!void,
) !void {
    // Walk meta_root; that's the authoritative "this node owns at least
    // one shard for (bucket,key)" marker.
    var meta_dir = data_dir.openDir(meta_root, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    defer meta_dir.close();

    var walker = try meta_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".meta")) continue;

        // Path is "<bucket>/<key>.meta", possibly with separators inside the key.
        // On Windows, walker uses backslashes — normalise.
        var path_buf: [1024]u8 = undefined;
        if (entry.path.len >= path_buf.len) continue;
        @memcpy(path_buf[0..entry.path.len], entry.path);
        for (path_buf[0..entry.path.len]) |*c| if (c.* == '\\') {
            c.* = '/';
        };
        const norm = path_buf[0..entry.path.len];

        const slash = std.mem.indexOfScalar(u8, norm, '/') orelse continue;
        const bucket = norm[0..slash];
        const key_with_ext = norm[slash + 1 ..];
        if (!std.mem.endsWith(u8, key_with_ext, ".meta")) continue;
        const key = key_with_ext[0 .. key_with_ext.len - ".meta".len];

        try visit(visit_ctx, bucket, key);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "shard round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try putShard(tmp.dir, "b", "k", 3, "hello");
    const got = (try getShard(tmp.dir, "b", "k", 3, std.testing.allocator)).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("hello", got);
    try deleteShard(tmp.dir, "b", "k", 3);
    try std.testing.expect((try getShard(tmp.dir, "b", "k", 3, std.testing.allocator)) == null);
}

test "meta round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try putMeta(tmp.dir, "b", "key/with/slashes", "{}");
    const got = (try getMeta(tmp.dir, "b", "key/with/slashes", std.testing.allocator)).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("{}", got);
}

const VisitorCtx = struct {
    found: std.ArrayList([]u8),
    allocator: Allocator,
};

fn collectVisitor(ctx: *anyopaque, bucket: []const u8, key: []const u8) anyerror!void {
    const v: *VisitorCtx = @ptrCast(@alignCast(ctx));
    const s = try std.fmt.allocPrint(v.allocator, "{s}/{s}", .{ bucket, key });
    try v.found.append(v.allocator, s);
}

test "localShardIndex finds the stored shard index" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(@as(?u8, null), try localShardIndex(tmp.dir, "b", "k"));
    try putShard(tmp.dir, "b", "k", 5, "payload");
    try std.testing.expectEqual(@as(?u8, 5), try localShardIndex(tmp.dir, "b", "k"));
}

test "forEachLocalKey lists keys with meta" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try putMeta(tmp.dir, "buk", "alpha", "{}");
    try putMeta(tmp.dir, "buk", "nested/beta", "{}");

    var v: VisitorCtx = .{ .found = .{}, .allocator = std.testing.allocator };
    defer {
        for (v.found.items) |s| std.testing.allocator.free(s);
        v.found.deinit(std.testing.allocator);
    }
    try forEachLocalKey(tmp.dir, std.testing.allocator, &v, collectVisitor);
    try std.testing.expectEqual(@as(usize, 2), v.found.items.len);
}
