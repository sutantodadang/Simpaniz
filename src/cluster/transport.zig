//! Pluggable shard transport for the cluster runtime.
//!
//! The cluster runtime scatters shards to N nodes during PUT and gathers
//! them back during GET. The actual transport (local disk, in-process
//! channel, HTTP to peers) is abstracted behind this vtable so the
//! orchestrator can be unit-tested without a network.
//!
//! Implementations:
//!   - `LocalTransport` — every "node" is a subdirectory on the local
//!     filesystem. Used by tests and by the single-node fallback path.
//!   - `HttpTransport`  — PUT/GET/DELETE shards and metadata through the
//!     internal `/_simpaniz/...` endpoints.

const std = @import("std");
const Allocator = std.mem.Allocator;
const disk = @import("disk_store.zig");
const types = @import("../storage/types.zig");
const xml = @import("../xml.zig");
const util = @import("../util.zig");

pub const ShardId = struct {
    bucket: []const u8,
    key: []const u8,
    /// Total ordering across (k+m) shards.
    index: u8,
};

pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        putShard: *const fn (ctx: *anyopaque, node: usize, sid: ShardId, data: []const u8) anyerror!void,
        getShard: *const fn (ctx: *anyopaque, node: usize, sid: ShardId, allocator: Allocator) anyerror!?[]u8,
        deleteShard: *const fn (ctx: *anyopaque, node: usize, sid: ShardId) anyerror!void,
        putMeta: *const fn (ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void,
        getMeta: *const fn (ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) anyerror!?[]u8,
        deleteMeta: *const fn (ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8) anyerror!void,
        /// One page of a node's LOCAL sorted meta-key listing (no delimiter
        /// collapsing — that happens only after the cross-node merge in
        /// `list_merge.zig`). Used to build cluster-wide `ListObjectsV2`
        /// without any node ever FS-walking another node's disk.
        listMeta: *const fn (ctx: *anyopaque, node: usize, bucket: []const u8, opts: types.ListOpts, allocator: Allocator) anyerror!types.ListPage,
        /// Append one stripe's worth of bytes to shard `sid` at logical
        /// position `seq` (0-based stripe index). Idempotent: replaying the
        /// same `seq` with identical `data.len` after it already landed is a
        /// no-op success. Any other length mismatch is `error.SeqMismatch`.
        appendShardChunk: *const fn (ctx: *anyopaque, node: usize, sid: ShardId, seq: u64, data: []const u8) anyerror!void,
        /// Read up to `buf.len` bytes starting at byte `offset` in shard
        /// `sid`'s file. Returns the number of bytes actually read (may be
        /// less than `buf.len` at EOF). Missing shard -> `error.ShardMissing`.
        getShardRange: *const fn (ctx: *anyopaque, node: usize, sid: ShardId, offset: u64, buf: []u8) anyerror!usize,
        /// Total byte length of shard `sid`'s file. Missing shard ->
        /// `error.ShardMissing`.
        statShard: *const fn (ctx: *anyopaque, node: usize, sid: ShardId) anyerror!u64,
    };

    pub inline fn putShard(self: Transport, node: usize, sid: ShardId, data: []const u8) !void {
        return self.vtable.putShard(self.ctx, node, sid, data);
    }
    pub inline fn getShard(self: Transport, node: usize, sid: ShardId, allocator: Allocator) !?[]u8 {
        return self.vtable.getShard(self.ctx, node, sid, allocator);
    }
    pub inline fn deleteShard(self: Transport, node: usize, sid: ShardId) !void {
        return self.vtable.deleteShard(self.ctx, node, sid);
    }
    pub inline fn appendShardChunk(self: Transport, node: usize, sid: ShardId, seq: u64, data: []const u8) !void {
        return self.vtable.appendShardChunk(self.ctx, node, sid, seq, data);
    }
    pub inline fn getShardRange(self: Transport, node: usize, sid: ShardId, offset: u64, buf: []u8) !usize {
        return self.vtable.getShardRange(self.ctx, node, sid, offset, buf);
    }
    pub inline fn statShard(self: Transport, node: usize, sid: ShardId) !u64 {
        return self.vtable.statShard(self.ctx, node, sid);
    }
    pub inline fn putMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8, data: []const u8) !void {
        return self.vtable.putMeta(self.ctx, node, bucket, key, data);
    }
    pub inline fn getMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) !?[]u8 {
        return self.vtable.getMeta(self.ctx, node, bucket, key, allocator);
    }
    pub inline fn deleteMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8) !void {
        return self.vtable.deleteMeta(self.ctx, node, bucket, key);
    }
    pub inline fn listMeta(self: Transport, node: usize, bucket: []const u8, opts: types.ListOpts, allocator: Allocator) !types.ListPage {
        return self.vtable.listMeta(self.ctx, node, bucket, opts, allocator);
    }
};

/// One-directory-per-node transport, useful for tests and single-process
/// multi-disk simulations.
pub const LocalTransport = struct {
    root: std.fs.Dir,
    node_count: usize,

    pub fn init(root: std.fs.Dir, node_count: usize) LocalTransport {
        return .{ .root = root, .node_count = node_count };
    }

    pub fn transport(self: *LocalTransport) Transport {
        return .{ .ctx = self, .vtable = &.{
            .putShard = put,
            .getShard = get,
            .deleteShard = del,
            .putMeta = putMeta,
            .getMeta = getMeta,
            .deleteMeta = delMeta,
            .appendShardChunk = appendChunk,
            .getShardRange = getRange,
            .statShard = statShardFn,
            .listMeta = listMeta,
        } };
    }

    fn pathFor(buf: []u8, node: usize, sid: ShardId) ![]const u8 {
        return std.fmt.bufPrint(buf, "node{d}/{s}/{s}/{d}.shard", .{
            node, sid.bucket, sid.key, sid.index,
        });
    }

    fn metaPathFor(buf: []u8, node: usize, bucket: []const u8, key: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "node{d}/_meta/{s}/{s}.meta", .{ node, bucket, key });
    }

    fn metaDirFor(buf: []u8, node: usize, bucket: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "node{d}/_meta/{s}", .{ node, bucket });
    }

    fn put(ctx: *anyopaque, node: usize, sid: ShardId, data: []const u8) anyerror!void {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        if (std.fs.path.dirname(p)) |dir| try self.root.makePath(dir);
        var f = try self.root.createFile(p, .{ .truncate = true });
        defer f.close();
        try f.writeAll(data);
    }

    fn get(ctx: *anyopaque, node: usize, sid: ShardId, allocator: Allocator) anyerror!?[]u8 {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        var f = self.root.openFile(p, .{}) catch |e| switch (e) {
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

    /// Append `data` (one stripe's chunk) to shard `sid`'s file at logical
    /// stripe index `seq`. If the file's current length equals
    /// `seq * data.len`, append lands normally. If it already equals
    /// `(seq + 1) * data.len`, the write was already applied (retry) and
    /// this is a no-op. Anything else is `error.SeqMismatch`.
    fn appendChunk(ctx: *anyopaque, node: usize, sid: ShardId, seq: u64, data: []const u8) anyerror!void {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        if (std.fs.path.dirname(p)) |dir| try self.root.makePath(dir);
        var f = try self.root.createFile(p, .{ .truncate = false, .read = true });
        defer f.close();
        const stat = try f.stat();
        const expected_before = seq * data.len;
        if (stat.size == expected_before) {
            try f.seekTo(expected_before);
            try f.writeAll(data);
        } else if (stat.size == expected_before + data.len) {
            return; // idempotent replay of an already-applied append
        } else {
            return error.SeqMismatch;
        }
    }

    /// Read up to `buf.len` bytes starting at `offset` from shard `sid`'s
    /// file. Returns the number of bytes actually read.
    fn getRange(ctx: *anyopaque, node: usize, sid: ShardId, offset: u64, buf: []u8) anyerror!usize {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        var f = self.root.openFile(p, .{}) catch |e| switch (e) {
            error.FileNotFound => return error.ShardMissing,
            else => return e,
        };
        defer f.close();
        try f.seekTo(offset);
        return try f.readAll(buf);
    }

    fn statShardFn(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!u64 {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        var f = self.root.openFile(p, .{}) catch |e| switch (e) {
            error.FileNotFound => return error.ShardMissing,
            else => return e,
        };
        defer f.close();
        const stat = try f.stat();
        return stat.size;
    }

    fn del(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!void {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try pathFor(&pb, node, sid);
        self.root.deleteFile(p) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
    }

    fn putMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try metaPathFor(&pb, node, bucket, key);
        if (std.fs.path.dirname(p)) |dir| try self.root.makePath(dir);
        var f = try self.root.createFile(p, .{ .truncate = true });
        defer f.close();
        try f.writeAll(data);
    }

    fn getMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) anyerror!?[]u8 {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try metaPathFor(&pb, node, bucket, key);
        var f = self.root.openFile(p, .{}) catch |e| switch (e) {
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

    fn delMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8) anyerror!void {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const p = try metaPathFor(&pb, node, bucket, key);
        self.root.deleteFile(p) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
    }

    /// Test/simulation-only listing: a plain FS-walk-and-sort over
    /// `node{N}/_meta/<bucket>/` (no LSM index, no delimiter collapsing —
    /// mirrors what the real `list_index.Index.list()` returns: a flat,
    /// sorted, prefix/bound-filtered page). Fine for tests since
    /// `LocalTransport` is only ever used with small in-memory fixtures.
    fn listMeta(ctx: *anyopaque, node: usize, bucket: []const u8, opts: types.ListOpts, allocator: Allocator) anyerror!types.ListPage {
        const self: *LocalTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.node_count) return error.InvalidNode;
        var pb: [512]u8 = undefined;
        const dir_path = try metaDirFor(&pb, node, bucket);
        var bd = self.root.openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return .{ .objects = &.{}, .common_prefixes = &.{}, .is_truncated = false, .next_continuation_token = "" },
            else => return e,
        };
        defer bd.close();

        // `path` is the full allocation (freed below); `key` is a slice
        // into it with the `.meta` suffix stripped — never freed directly
        // (freeing a truncated slice of a GPA allocation is invalid).
        const Item = struct { path: []u8, key: []const u8, meta: disk.ObjectMeta };
        var all = std.ArrayList(Item){};
        defer {
            for (all.items) |it| {
                allocator.free(it.path);
                allocator.free(it.meta.content_type);
            }
            all.deinit(allocator);
        }

        var walker = try bd.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".meta")) continue;
            const normalized = try allocator.dupe(u8, entry.path);
            for (normalized) |*c| if (c.* == '\\') {
                c.* = '/';
            };
            const key = normalized[0 .. normalized.len - ".meta".len];

            var f = bd.openFile(entry.path, .{}) catch {
                allocator.free(normalized);
                continue;
            };
            defer f.close();
            const stat = try f.stat();
            const buf = try allocator.alloc(u8, stat.size);
            defer allocator.free(buf);
            const n = try f.readAll(buf);
            if (n != buf.len) {
                allocator.free(normalized);
                continue;
            }
            const meta = disk.ObjectMeta.fromJson(allocator, buf) catch {
                allocator.free(normalized);
                continue;
            };
            try all.append(allocator, .{ .path = normalized, .key = key, .meta = meta });
        }

        std.mem.sort(Item, all.items, {}, struct {
            fn lt(_: void, a: Item, b: Item) bool {
                return std.mem.lessThan(u8, a.key, b.key);
            }
        }.lt);

        var bound: []const u8 = opts.prefix;
        var bound_inclusive = true;
        if (opts.continuation_token.len > 0) {
            bound = opts.continuation_token;
        } else if (opts.start_after.len > 0) {
            bound = opts.start_after;
            bound_inclusive = false;
        }

        const max = if (opts.max_keys == 0 or opts.max_keys > 1000) 1000 else opts.max_keys;
        var objects = std.ArrayList(xml.ObjectInfo){};
        var truncated = false;
        var next_token: []const u8 = "";

        for (all.items) |item| {
            if (opts.prefix.len > 0 and !std.mem.startsWith(u8, item.key, opts.prefix)) continue;
            if (bound.len > 0) {
                const cmp_lt = std.mem.lessThan(u8, item.key, bound);
                const cmp_eq = std.mem.eql(u8, item.key, bound);
                if (cmp_lt or (cmp_eq and !bound_inclusive)) continue;
            }
            if (objects.items.len >= max) {
                truncated = true;
                next_token = try allocator.dupe(u8, item.key);
                break;
            }
            var lm_buf: [32]u8 = undefined;
            try objects.append(allocator, .{
                .key = try allocator.dupe(u8, item.key),
                .last_modified = try allocator.dupe(u8, util.formatIso8601(&lm_buf, @as(i128, item.meta.last_modified) * std.time.ns_per_s)),
                .etag = try std.fmt.allocPrint(allocator, "\"{s}\"", .{item.meta.etag}),
                .size = item.meta.original_size,
            });
        }

        return .{
            .objects = try objects.toOwnedSlice(allocator),
            .common_prefixes = &.{},
            .is_truncated = truncated,
            .next_continuation_token = next_token,
        };
    }
};

test "LocalTransport round-trips a shard" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = LocalTransport.init(tmp.dir, 3);
    const t = lt.transport();
    const sid: ShardId = .{ .bucket = "buk", .key = "k1", .index = 2 };

    const payload = "shard-bytes";
    try t.putShard(1, sid, payload);

    const got = (try t.getShard(1, sid, std.testing.allocator)).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(payload, got);

    const missing = try t.getShard(0, sid, std.testing.allocator);
    try std.testing.expect(missing == null);

    try t.deleteShard(1, sid);
    const after = try t.getShard(1, sid, std.testing.allocator);
    try std.testing.expect(after == null);
}

test "LocalTransport appendShardChunk validates seq and reads back ranges" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = LocalTransport.init(tmp.dir, 2);
    const t = lt.transport();
    const sid: ShardId = .{ .bucket = "buk", .key = "k1", .index = 0 };

    try t.appendShardChunk(0, sid, 0, "AAAA");
    // Wrong seq (skips ahead) must fail.
    try std.testing.expectError(error.SeqMismatch, t.appendShardChunk(0, sid, 2, "CCCC"));
    // Replay of the already-applied seq 0 chunk is a no-op success.
    try t.appendShardChunk(0, sid, 0, "AAAA");
    try t.appendShardChunk(0, sid, 1, "BBBB");

    try std.testing.expectEqual(@as(u64, 8), try t.statShard(0, sid));

    var buf: [4]u8 = undefined;
    const n = try t.getShardRange(0, sid, 4, &buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualStrings("BBBB", buf[0..n]);

    try std.testing.expectError(error.ShardMissing, t.statShard(1, sid));
}

test "LocalTransport round-trips meta" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var lt = LocalTransport.init(tmp.dir, 2);
    const t = lt.transport();
    try t.putMeta(0, "b", "k", "{\"x\":1}");
    const got = (try t.getMeta(0, "b", "k", std.testing.allocator)).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("{\"x\":1}", got);
    try t.deleteMeta(0, "b", "k");
    try std.testing.expect((try t.getMeta(0, "b", "k", std.testing.allocator)) == null);
}
