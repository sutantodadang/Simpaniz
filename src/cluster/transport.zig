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
//!   - `HttpTransport`  — TODO. Will PUT/GET shards to peers via the
//!     internal `/_simpaniz/shards/...` endpoint.

const std = @import("std");
const Allocator = std.mem.Allocator;

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
    pub inline fn putMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8, data: []const u8) !void {
        return self.vtable.putMeta(self.ctx, node, bucket, key, data);
    }
    pub inline fn getMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) !?[]u8 {
        return self.vtable.getMeta(self.ctx, node, bucket, key, allocator);
    }
    pub inline fn deleteMeta(self: Transport, node: usize, bucket: []const u8, key: []const u8) !void {
        return self.vtable.deleteMeta(self.ctx, node, bucket, key);
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
