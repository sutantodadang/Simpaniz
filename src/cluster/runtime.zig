//! Cluster runtime — wires together config, transport, on-disk store,
//! and orchestrator. Owned by the server's top-level `Context`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const config_mod = @import("config.zig");
pub const ClusterConfig = config_mod.ClusterConfig;
const orch_mod = @import("orchestrator.zig");
pub const Orchestrator = orch_mod.Orchestrator;
const http_transport_mod = @import("http_transport.zig");
pub const HttpTransport = http_transport_mod.HttpTransport;
const transport_mod = @import("transport.zig");
const disk = @import("disk_store.zig");
const replication_mod = @import("replication.zig");
pub const Replicator = replication_mod.Replicator;

pub const ObjectMeta = struct {
    shard_size: usize,
    original_size: usize,
    etag: [32]u8, // md5 hex (32 chars)
    content_type: []const u8,
    last_modified: i64, // unix seconds
    encrypted: bool = false,

    pub fn toJson(self: ObjectMeta, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "{{\"v\":1,\"shard_size\":{d},\"original_size\":{d},\"etag\":\"{s}\",\"content_type\":\"{s}\",\"last_modified\":{d},\"encrypted\":{}}}",
            .{ self.shard_size, self.original_size, self.etag, self.content_type, self.last_modified, self.encrypted },
        );
    }

    pub fn fromJson(allocator: Allocator, json: []const u8) !ObjectMeta {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        var m: ObjectMeta = .{
            .shard_size = @intCast(obj.get("shard_size").?.integer),
            .original_size = @intCast(obj.get("original_size").?.integer),
            .etag = undefined,
            .content_type = "",
            .last_modified = obj.get("last_modified").?.integer,
            .encrypted = if (obj.get("encrypted")) |v| v.bool else false,
        };
        const etag_s = obj.get("etag").?.string;
        if (etag_s.len != 32) return error.BadMeta;
        @memcpy(&m.etag, etag_s);
        const ct = obj.get("content_type").?.string;
        m.content_type = try allocator.dupe(u8, ct);
        return m;
    }
};

pub const ClusterRuntime = struct {
    allocator: Allocator,
    config: *ClusterConfig,
    data_dir: std.fs.Dir,
    http_transport: HttpTransport,
    metrics: HttpTransport.Metrics = .{},
    orchestrator: Orchestrator,
    /// Owned slice of node-id pointers for orchestrator.
    nodes: [][]const u8,
    /// Cross-cluster replicator (null if no targets configured).
    replication: ?*Replicator = null,

    pub fn init(allocator: Allocator, config: *ClusterConfig, data_dir: std.fs.Dir) !*ClusterRuntime {
        const rt = try allocator.create(ClusterRuntime);
        errdefer allocator.destroy(rt);

        rt.* = .{
            .allocator = allocator,
            .config = config,
            .data_dir = data_dir,
            .http_transport = HttpTransport.init(allocator, config, data_dir),
            .orchestrator = undefined,
            .nodes = undefined,
        };
        rt.http_transport.metrics = &rt.metrics;

        rt.nodes = try allocator.alloc([]const u8, config.peers.len);
        errdefer allocator.free(rt.nodes);
        for (config.peers, 0..) |p, i| rt.nodes[i] = p.id;

        rt.orchestrator = try Orchestrator.init(
            allocator,
            rt.nodes,
            config.ec_k,
            config.ec_m,
            rt.http_transport.transport(),
        );
        return rt;
    }

    pub fn deinit(self: *ClusterRuntime) void {
        if (self.replication) |r| {
            replication_mod.current_runtime = null;
            r.deinit();
        }
        self.orchestrator.deinit();
        self.allocator.free(self.nodes);
        self.allocator.destroy(self);
    }

    /// Spin up the SSR worker if `repl_targets_raw` is non-empty.
    /// Safe to call once after init; subsequent calls are no-ops.
    pub fn startReplication(self: *ClusterRuntime, auth_header: ?[]const u8) !void {
        if (self.replication != null) return;
        if (self.config.repl_targets_raw.len == 0) return;
        const r = try Replicator.init(self.allocator, self.config.repl_targets_raw, auth_header);
        errdefer r.deinit();
        // Best-effort journal — failure is logged but not fatal.
        r.attachJournal(self.data_dir) catch |e| {
            std.log.warn("ssr: journal init failed: {any}", .{e});
        };
        self.replication = r;
        replication_mod.current_runtime = self;
        try r.start();
    }

    /// Replicate metadata to every node holding a shard for this key.
    /// On read we accept the first response; on write we tolerate up to
    /// `m` failures.
    pub fn writeMeta(self: *ClusterRuntime, bucket: []const u8, key: []const u8, meta: ObjectMeta) !void {
        const json = try meta.toJson(self.allocator);
        defer self.allocator.free(json);

        var placement_buf: [32]usize = undefined;
        const k_plus_m = self.config.shardCount();
        if (k_plus_m > placement_buf.len) return error.TooManyShards;
        const placement = placement_buf[0..k_plus_m];
        try self.orchestrator.placement(bucket, key, placement);

        var ok_count: usize = 0;
        for (placement) |node| {
            self.http_transport.transport().putMeta(node, bucket, key, json) catch continue;
            ok_count += 1;
        }
        if (ok_count + @as(usize, self.config.ec_m) < k_plus_m) return error.MetaQuorumFailed;
    }

    pub fn readMeta(self: *ClusterRuntime, bucket: []const u8, key: []const u8, allocator: Allocator) !?ObjectMeta {
        var placement_buf: [32]usize = undefined;
        const k_plus_m = self.config.shardCount();
        if (k_plus_m > placement_buf.len) return error.TooManyShards;
        const placement = placement_buf[0..k_plus_m];
        try self.orchestrator.placement(bucket, key, placement);

        for (placement) |node| {
            const r = self.http_transport.transport().getMeta(node, bucket, key, allocator) catch continue;
            if (r) |bytes| {
                defer allocator.free(bytes);
                return try ObjectMeta.fromJson(allocator, bytes);
            }
        }
        return null;
    }

    pub fn deleteMeta(self: *ClusterRuntime, bucket: []const u8, key: []const u8) !void {
        var placement_buf: [32]usize = undefined;
        const k_plus_m = self.config.shardCount();
        if (k_plus_m > placement_buf.len) return error.TooManyShards;
        const placement = placement_buf[0..k_plus_m];
        try self.orchestrator.placement(bucket, key, placement);

        for (placement) |node| {
            self.http_transport.transport().deleteMeta(node, bucket, key) catch {};
        }
    }

    pub const BucketOp = enum { create, delete };

    /// Replicate a bucket create/delete to every peer in the cluster.
    /// Tolerates up to `m` failures (matches shard write quorum).
    pub fn replicateBucket(self: *ClusterRuntime, bucket: []const u8, op: BucketOp) !void {
        const total = self.config.peers.len;
        if (total == 0) return;
        var ok_count: usize = 0;
        const method: []const u8 = if (op == .create) "PUT" else "DELETE";
        for (0..total) |i| {
            self.http_transport.bucketOp(i, method, bucket) catch continue;
            ok_count += 1;
        }
        if (ok_count + @as(usize, self.config.ec_m) < total) return error.BucketReplicationQuorumFailed;
    }
};

test "ObjectMeta json round-trip" {
    var m: ObjectMeta = .{
        .shard_size = 1024,
        .original_size = 4000,
        .etag = "0123456789abcdef0123456789abcdef".*,
        .content_type = "text/plain",
        .last_modified = 1700000000,
        .encrypted = false,
    };
    const j = try m.toJson(std.testing.allocator);
    defer std.testing.allocator.free(j);

    const round = try ObjectMeta.fromJson(std.testing.allocator, j);
    defer std.testing.allocator.free(round.content_type);
    try std.testing.expectEqual(m.shard_size, round.shard_size);
    try std.testing.expectEqual(m.original_size, round.original_size);
    try std.testing.expectEqualStrings(&m.etag, &round.etag);
    try std.testing.expectEqualStrings(m.content_type, round.content_type);
}
