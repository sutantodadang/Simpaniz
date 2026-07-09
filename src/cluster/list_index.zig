//! Cluster-mode LSM-lite listing index over the local `.simpaniz-meta` tree.
//!
//! Each node maintains its OWN index over the cluster meta files it stores
//! locally (`.simpaniz-meta/<bucket>/<key>.meta`), reusing `index.zig`'s
//! generic LSM-lite machinery (`Manager`/`BootstrapSource`) via a pluggable
//! bootstrap adapter that reads cluster `ObjectMeta` JSON instead of real
//! object files. Cluster-wide `ListObjectsV2` merges sorted pages from every
//! node's local index — see `list_merge.zig`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const index_mod = @import("../index.zig");
const disk = @import("disk_store.zig");
const types = @import("../storage/types.zig");

/// Suffix stripped from a walked file's relative path to produce the
/// logical object key (mirrors `disk_store.zig`'s `.meta` sidecar naming).
const meta_suffix = ".meta";

/// `BootstrapSource.read` adapter: parses a `.meta` JSON sidecar (rather
/// than stat'ing/reading a real object file) into `index_mod.MetaVals`.
fn readClusterMetaForIndex(bucket_dir: Dir, gpa: Allocator, path: []const u8) anyerror!index_mod.MetaVals {
    var f = try bucket_dir.openFile(path, .{});
    defer f.close();
    const stat = try f.stat();
    const buf = try gpa.alloc(u8, stat.size);
    defer gpa.free(buf);
    const n = try f.readAll(buf);
    if (n != buf.len) return error.ShortRead;

    const meta = try disk.ObjectMeta.fromJson(gpa, buf);
    defer gpa.free(meta.content_type);
    return .{
        .size = meta.original_size,
        .mtime_ns = @as(i128, meta.last_modified) * std.time.ns_per_s,
        .etag = try gpa.dupe(u8, &meta.etag),
    };
}

/// Bootstrap source for cluster meta: strip `.meta`, parse cluster JSON.
pub const bootstrap_source: index_mod.BootstrapSource = .{
    .key_suffix = meta_suffix,
    .read = readClusterMetaForIndex,
};

/// Cluster-scoped listing index: one per `ClusterRuntime`, rooted at this
/// node's `.simpaniz-meta` directory (created on demand — a brand-new node
/// may not have written any meta yet).
pub const Index = struct {
    manager: index_mod.Manager,
    meta_root: Dir,

    pub fn init(gpa: Allocator, data_dir: Dir) !Index {
        const meta_root = try data_dir.makeOpenPath(disk.meta_root, .{ .iterate = true });
        return .{ .manager = index_mod.Manager.initWithSource(gpa, meta_root, bootstrap_source), .meta_root = meta_root };
    }

    pub fn deinit(self: *Index) void {
        self.manager.deinit();
        self.meta_root.close();
    }

    /// Never fails the request path — logs and drops the update on error
    /// (mirrors `index_mod.Manager.noteUpsert`). Ensures the bucket's
    /// `.simpaniz-meta/<bucket>/` directory exists first: in production this
    /// is always already true (the caller writes the `.meta` sidecar to disk
    /// before calling here), but a defensive `makePath` keeps this safe to
    /// call standalone too (e.g. from tests) without requiring callers to
    /// know the on-disk layout.
    pub fn noteUpsert(self: *Index, bucket: []const u8, key: []const u8, size: u64, mtime_ns: i128, etag: []const u8) void {
        self.meta_root.makePath(bucket) catch {};
        self.manager.noteUpsert(bucket, key, size, mtime_ns, etag);
    }

    /// Never fails the request path.
    pub fn noteDelete(self: *Index, bucket: []const u8, key: []const u8) void {
        self.meta_root.makePath(bucket) catch {};
        self.manager.noteDelete(bucket, key);
    }

    /// List this node's local slice of a bucket. Returns an empty
    /// (non-truncated) page if this node has never stored any meta for the
    /// bucket at all (no `.simpaniz-meta/<bucket>/` directory yet) — that's
    /// a normal "nothing here locally" outcome in cluster listing, not a
    /// failure, since keys are sharded/replicated across a subset of nodes.
    pub fn list(self: *Index, allocator: Allocator, bucket: []const u8, opts: types.ListOpts) !types.ListPage {
        return self.manager.list(allocator, bucket, opts) catch |e| switch (e) {
            error.FileNotFound => .{ .objects = &.{}, .common_prefixes = &.{}, .is_truncated = false, .next_continuation_token = "" },
            else => return e,
        };
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "Index bootstraps from .simpaniz-meta JSON sidecars and lists sorted keys" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Seed a couple of cluster meta files directly (as disk_store.putMeta
    // would), then let the index bootstrap-walk discover them.
    const m1: disk.ObjectMeta = .{ .shard_size = 5, .original_size = 5, .etag = "00000000000000000000000000000001".*, .content_type = "text/plain", .last_modified = 1000 };
    const m2: disk.ObjectMeta = .{ .shard_size = 5, .original_size = 5, .etag = "00000000000000000000000000000002".*, .content_type = "text/plain", .last_modified = 2000 };
    const j1 = try m1.toJson(std.testing.allocator);
    defer std.testing.allocator.free(j1);
    const j2 = try m2.toJson(std.testing.allocator);
    defer std.testing.allocator.free(j2);
    try disk.putMeta(tmp.dir, "buk", "b", j1);
    try disk.putMeta(tmp.dir, "buk", "a", j2);

    var idx = try Index.init(std.testing.allocator, tmp.dir);
    defer idx.deinit();

    const page = try idx.list(std.testing.allocator, "buk", .{});
    defer index_mod.freePage(std.testing.allocator, page);
    try std.testing.expectEqual(@as(usize, 2), page.objects.len);
    try std.testing.expectEqualStrings("a", page.objects[0].key);
    try std.testing.expectEqualStrings("b", page.objects[1].key);
    try std.testing.expect(!page.is_truncated);
}

test "Index.list on a never-touched bucket returns empty, not an error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var idx = try Index.init(std.testing.allocator, tmp.dir);
    defer idx.deinit();

    const page = try idx.list(std.testing.allocator, "nope", .{});
    try std.testing.expectEqual(@as(usize, 0), page.objects.len);
    try std.testing.expect(!page.is_truncated);
}

test "Index.noteUpsert/noteDelete update the live index without a restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var idx = try Index.init(std.testing.allocator, tmp.dir);
    defer idx.deinit();

    idx.noteUpsert("buk", "k1", 10, 1000, "0123456789abcdef0123456789abcdef");
    idx.noteUpsert("buk", "k2", 20, 2000, "fedcba9876543210fedcba9876543210");

    const page = try idx.list(std.testing.allocator, "buk", .{});
    defer index_mod.freePage(std.testing.allocator, page);
    try std.testing.expectEqual(@as(usize, 2), page.objects.len);

    idx.noteDelete("buk", "k1");
    const page2 = try idx.list(std.testing.allocator, "buk", .{});
    defer index_mod.freePage(std.testing.allocator, page2);
    try std.testing.expectEqual(@as(usize, 1), page2.objects.len);
    try std.testing.expectEqualStrings("k2", page2.objects[0].key);
}
