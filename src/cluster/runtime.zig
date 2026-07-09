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
const membership_mod = @import("membership.zig");
pub const Membership = membership_mod.Membership;
const list_index_mod = @import("list_index.zig");
const list_merge_mod = @import("list_merge.zig");
const types = @import("../storage/types.zig");

/// Re-exported from `disk_store.zig` (moved there so both this module and
/// `list_index.zig` — the index-backed cluster-listing bootstrap adapter —
/// can parse `.meta` JSON without an import cycle between the two).
pub const ObjectMeta = disk.ObjectMeta;

pub const ClusterRuntime = struct {
    allocator: Allocator,
    config: *ClusterConfig,
    data_dir: std.fs.Dir,
    http_transport: HttpTransport,
    metrics: HttpTransport.Metrics = .{},
    orchestrator: Orchestrator,
    /// Owned slice of node-id pointers for orchestrator (init-time
    /// fallback; live placement goes through `membership` once attached).
    nodes: [][]const u8,
    /// Cluster membership: health probing, gossip, dynamic join. Always
    /// non-null when `ClusterRuntime` is constructed (cluster mode).
    membership: *Membership,
    /// Cross-cluster replicator (null if no targets configured).
    replication: ?*Replicator = null,
    /// This node's local LSM-lite listing index over `.simpaniz-meta`
    /// (index-backed cluster listing — see `listObjects`/`list_merge.zig`).
    list_index: list_index_mod.Index,

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
            .membership = undefined,
            .list_index = undefined,
        };
        rt.http_transport.metrics = &rt.metrics;

        rt.nodes = try allocator.alloc([]const u8, config.peers.len);
        errdefer allocator.free(rt.nodes);
        for (config.peers, 0..) |p, i| rt.nodes[i] = p.id;

        rt.membership = try Membership.init(allocator, config, data_dir);
        errdefer rt.membership.deinit();

        rt.list_index = try list_index_mod.Index.init(allocator, data_dir);
        errdefer rt.list_index.deinit();
        rt.http_transport.list_index = &rt.list_index;

        rt.orchestrator = try Orchestrator.init(
            allocator,
            rt.nodes,
            config.ec_k,
            config.ec_m,
            rt.http_transport.transport(),
        );
        rt.orchestrator.membership = rt.membership;
        rt.http_transport.membership = rt.membership;

        return rt;
    }

    pub fn deinit(self: *ClusterRuntime) void {
        if (self.replication) |r| {
            replication_mod.current_runtime = null;
            r.deinit();
        }
        self.membership.deinit();
        self.orchestrator.deinit();
        self.list_index.deinit();
        self.allocator.free(self.nodes);
        self.allocator.destroy(self);
    }

    /// Cluster-wide `ListObjectsV2`: merges every usable node's local sorted
    /// meta-key page (via `HttpTransport.listMeta`, self-node short-
    /// circuited to the local index) into one paginated result. See
    /// `list_merge.zig` for the merge algorithm and its failure semantics
    /// (a peer fetch failing twice fails the WHOLE request rather than
    /// returning a partial listing).
    pub fn listObjects(self: *ClusterRuntime, allocator: Allocator, bucket: []const u8, opts: types.ListOpts) !types.ListPage {
        return list_merge_mod.merge(self.http_transport.transport(), self.membership, allocator, bucket, opts);
    }

    /// Start the membership health-probe thread. Safe to call once after
    /// init; the prober never blocks the request path.
    pub fn startMembership(self: *ClusterRuntime) !void {
        try self.membership.start(self.http_transport.pinger());
    }

    /// Announce this node to its configured peers via the internal join
    /// endpoint (only when `SIMPANIZ_JOIN` is set). Stops at the first
    /// peer that accepts the join and merges its returned membership view.
    /// Best-effort: logs and returns on failure rather than erroring the
    /// caller — a node that can't reach any peer yet still boots and will
    /// pick up membership via probes/gossip once peers are reachable.
    pub fn joinCluster(self: *ClusterRuntime) void {
        if (!self.config.join) return;
        const self_peer = self.config.peers[self.config.self_index];
        for (self.config.peers, 0..) |_, i| {
            if (i == self.config.self_index) continue;
            const body = self.http_transport.join(i, self_peer.id, self_peer.host, self_peer.port, self.allocator) catch continue;
            defer self.allocator.free(body);
            self.membership.mergeGossip(body) catch |e| {
                std.log.warn("cluster: join response merge failed: {any}", .{e});
            };
            std.log.info("cluster: joined via peer {s}", .{self.config.peers[i].id});
            return;
        }
        std.log.warn("cluster: SIMPANIZ_JOIN set but no configured peer accepted the join request", .{});
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
        // Meta must land on the SAME nodes the shard data does — use
        // write-placement (excludes draining/removed nodes), matching
        // `Orchestrator.put`'s target set.
        try self.orchestrator.writePlacement(bucket, key, placement);

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
