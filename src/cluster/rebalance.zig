//! Shard rebalancing on membership change.
//!
//! When a node joins (or a previously-down node's placement weight
//! changes), rendezvous hashing reassigns roughly `1/N` of shards to a
//! different owner. Objects written before the change are still physically
//! sitting on their OLD owner's disk; this sweep walks every locally
//! stored (bucket, key), recomputes placement under the CURRENT node list,
//! and for any shard this node holds that is no longer assigned to it:
//!
//!   1. stream-copies the shard bytes to the new owner (chunked
//!      `appendShardChunk`, skipping the copy if the new owner already has
//!      a full-length copy — e.g. a retried sweep after a partial failure),
//!   2. verifies the new owner's shard length matches,
//!   3. best-effort pushes local meta to the new owner too,
//!   4. deletes the local shard file only after the copy is verified.
//!
//! Reads stay correct throughout: HRW only ever moves ~1/N of a key's
//! shards at a time, the old owner keeps its copy until the new owner's
//! copy is verified, and `Orchestrator.getRangeStreaming`/`heal` tolerate
//! up to `m` missing shards regardless of which node is "correct" at any
//! given instant.
//!
//! The core migration logic (`runOnceCore`) is transport/orchestrator/
//! self-index generic so it can be driven against a `ClusterRuntime`
//! (`runOnce`, the production entry point) or directly in tests against a
//! synthetic multi-node local transport.

const std = @import("std");
const Allocator = std.mem.Allocator;
const disk = @import("disk_store.zig");
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;
const ShardId = transport_mod.ShardId;
const orchestrator_mod = @import("orchestrator.zig");
const Orchestrator = orchestrator_mod.Orchestrator;
const runtime_mod = @import("runtime.zig");
const membership_mod = @import("membership.zig");
const config_mod = @import("config.zig");
const list_index_mod = @import("list_index.zig");
const types_mod = @import("../storage/types.zig");

pub const Stats = struct {
    scanned: u64 = 0,
    moved: u64 = 0,
    deleted: u64 = 0,
    errors: u64 = 0,
};

/// Production entry point — sweeps `rt`'s locally stored keys, then lets the
/// node auto-complete its own drain (see `runOnceDraining`).
pub fn runOnce(rt: *runtime_mod.ClusterRuntime, allocator: Allocator) !Stats {
    return runOnceDraining(
        allocator,
        &rt.orchestrator,
        rt.http_transport.transport(),
        rt.data_dir,
        rt.config.self_index,
        rt.membership,
    );
}

/// Sweep once via `runOnceCore`, then — if the local node is currently
/// `draining` — auto-promote it to `removed` once the sweep leaves zero
/// local shards behind with zero errors. This is what lets a decommission
/// complete on its own without an external "is it done yet?" poll: since
/// `markDraining`/`mergeGossip` bump `Membership.generation`, the existing
/// interval-independent rebalance daemon (`server.zig`'s `rebalanceLoop`,
/// which wakes on either the configured interval OR a generation bump)
/// already reruns this promptly after a node is marked draining.
pub fn runOnceDraining(
    allocator: Allocator,
    orch: *Orchestrator,
    transport: Transport,
    data_dir: std.fs.Dir,
    self_index: usize,
    membership: *membership_mod.Membership,
) !Stats {
    const stats = try runOnceCore(allocator, orch, transport, data_dir, self_index);
    if (stats.errors == 0 and membership.stateOf(self_index) == .draining) {
        const has_shards = disk.hasAnyLocalShard(data_dir, allocator) catch true;
        if (!has_shards) {
            if (membership.idAt(self_index)) |id| {
                membership.markRemoved(id) catch |e| {
                    std.log.warn("rebalance: auto markRemoved failed: {any}", .{e});
                };
            }
        }
    }
    return stats;
}

/// Transport/orchestrator-generic core, reusable in tests against any
/// `Transport` implementation and any simulated `self_index`.
pub fn runOnceCore(
    allocator: Allocator,
    orch: *Orchestrator,
    transport: Transport,
    data_dir: std.fs.Dir,
    self_index: usize,
) !Stats {
    var stats: Stats = .{};
    var ctx: WalkCtx = .{
        .orch = orch,
        .transport = transport,
        .data_dir = data_dir,
        .self_index = self_index,
        .allocator = allocator,
        .stats = &stats,
    };
    try disk.forEachLocalKey(data_dir, allocator, &ctx, visit);
    return stats;
}

const WalkCtx = struct {
    orch: *Orchestrator,
    transport: Transport,
    data_dir: std.fs.Dir,
    self_index: usize,
    allocator: Allocator,
    stats: *Stats,
};

fn visit(raw: *anyopaque, bucket: []const u8, key: []const u8) anyerror!void {
    const ctx: *WalkCtx = @ptrCast(@alignCast(raw));
    ctx.stats.scanned += 1;
    const moved = migrateKeyCore(
        ctx.allocator,
        ctx.orch,
        ctx.transport,
        ctx.data_dir,
        ctx.self_index,
        bucket,
        key,
    ) catch |e| {
        std.log.warn("rebalance: migrate {s}/{s} failed: {any}", .{ bucket, key, e });
        ctx.stats.errors += 1;
        return;
    };
    ctx.stats.moved += moved;
    ctx.stats.deleted += moved;
}

/// Migrate every shard of (bucket, key) that `self_index` currently holds
/// but current placement no longer assigns to it. Returns the number of
/// shards migrated. A node can hold MORE than one shard of the same key
/// mid-rebalance (an earlier peer's sweep may push a shard here before our
/// own sweep runs), so every index must be examined — checking a single
/// index strands the others (directory-iteration order made this
/// Windows-pass/Linux-fail flaky before).
fn migrateKeyCore(
    allocator: Allocator,
    orch: *Orchestrator,
    transport: Transport,
    data_dir: std.fs.Dir,
    self_index: usize,
    bucket: []const u8,
    key: []const u8,
) !u64 {
    const total = orch.codec.shardCount();
    var place_buf: [32]usize = undefined;
    if (total > place_buf.len) return error.TooManyShards;
    const place = place_buf[0..total];
    try orch.writePlacement(bucket, key, place);

    var moved: u64 = 0;
    for (0..total) |idx| {
        const local_idx: u8 = @intCast(idx);
        if (migrateShard(allocator, transport, data_dir, self_index, bucket, key, local_idx, place[idx])) |did| {
            if (did) moved += 1;
        } else |e| return e;
    }
    return moved;
}

/// Migrate one locally-held shard to `new_owner` if misplaced. Returns
/// `true` when a shard was copied+verified+deleted, `false` when there is
/// nothing to do (shard not held locally, or already correctly placed).
fn migrateShard(
    allocator: Allocator,
    transport: Transport,
    data_dir: std.fs.Dir,
    self_index: usize,
    bucket: []const u8,
    key: []const u8,
    local_idx: u8,
    new_owner: usize,
) !bool {
    if (new_owner == self_index) return false; // still correctly placed
    const local_len = disk.statShard(data_dir, bucket, key, local_idx) catch |e| switch (e) {
        error.ShardMissing => return false, // we don't hold this index
        else => return e,
    };

    const meta_bytes = (try disk.getMeta(data_dir, bucket, key, allocator)) orelse return false;
    defer allocator.free(meta_bytes);
    const meta = try runtime_mod.ObjectMeta.fromJson(allocator, meta_bytes);
    defer allocator.free(meta.content_type);
    if (meta.shard_size == 0) return error.InvalidMeta;

    const sid: ShardId = .{ .bucket = bucket, .key = key, .index = local_idx };

    const already: u64 = transport.statShard(new_owner, sid) catch 0;
    if (already != local_len) {
        const chunk = meta.shard_size;
        if (local_len % chunk != 0) return error.CorruptShard;
        const n_stripes = local_len / chunk;

        const buf = try allocator.alloc(u8, chunk);
        defer allocator.free(buf);

        var seq: u64 = 0;
        while (seq < n_stripes) : (seq += 1) {
            const off: u64 = seq * chunk;
            const n = try disk.getShardRange(data_dir, bucket, key, local_idx, off, buf);
            if (n != chunk) return error.ShortRead;
            try transport.appendShardChunk(new_owner, sid, seq, buf);
        }
    }

    const verify_len = try transport.statShard(new_owner, sid);
    if (verify_len != local_len) return error.MigrationVerifyFailed;

    // Best-effort: the new owner should also carry the object's metadata.
    transport.putMeta(new_owner, bucket, key, meta_bytes) catch |e| {
        std.log.debug("rebalance: meta push to new owner failed: {any}", .{e});
    };

    try disk.deleteShard(data_dir, bucket, key, local_idx);
    return true;
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Multi-node local-disk transport for tests: node `i`'s data lives at
/// `dirs[i]`, laid out exactly like the real on-disk `disk_store` format
/// (`.simpaniz-shards/...`, `.simpaniz-meta/...`). This lets tests drive
/// the SAME `disk_store`-based migration path production code uses,
/// without needing real HTTP sockets between simulated nodes.
const DiskMultiTransport = struct {
    dirs: []std.fs.Dir,

    fn transport(self: *DiskMultiTransport) Transport {
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
            .listMeta = listMetaFn,
        } };
    }

    fn dirOf(ctx: *anyopaque, node: usize) !std.fs.Dir {
        const self: *DiskMultiTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.dirs.len) return error.InvalidNode;
        return self.dirs[node];
    }

    fn put(ctx: *anyopaque, node: usize, sid: ShardId, data: []const u8) anyerror!void {
        return disk.putShard(try dirOf(ctx, node), sid.bucket, sid.key, sid.index, data);
    }
    fn get(ctx: *anyopaque, node: usize, sid: ShardId, allocator: Allocator) anyerror!?[]u8 {
        return disk.getShard(try dirOf(ctx, node), sid.bucket, sid.key, sid.index, allocator);
    }
    fn del(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!void {
        return disk.deleteShard(try dirOf(ctx, node), sid.bucket, sid.key, sid.index);
    }
    fn putMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void {
        return disk.putMeta(try dirOf(ctx, node), bucket, key, data);
    }
    fn getMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) anyerror!?[]u8 {
        return disk.getMeta(try dirOf(ctx, node), bucket, key, allocator);
    }
    fn delMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8) anyerror!void {
        return disk.deleteMeta(try dirOf(ctx, node), bucket, key);
    }
    fn appendChunk(ctx: *anyopaque, node: usize, sid: ShardId, seq: u64, data: []const u8) anyerror!void {
        return disk.appendShardChunk(try dirOf(ctx, node), sid.bucket, sid.key, sid.index, seq, data);
    }
    fn getRange(ctx: *anyopaque, node: usize, sid: ShardId, offset: u64, buf: []u8) anyerror!usize {
        return disk.getShardRange(try dirOf(ctx, node), sid.bucket, sid.key, sid.index, offset, buf);
    }
    fn statShardFn(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!u64 {
        return disk.statShard(try dirOf(ctx, node), sid.bucket, sid.key, sid.index);
    }
    /// Builds a fresh `list_index.Index` over the node's dir on every call
    /// (bootstrap is idempotent/incremental — see `index.zig`'s
    /// `tryOpenExisting`) — fine for tests, keeps `DiskMultiTransport`
    /// stateless like its other methods.
    fn listMetaFn(ctx: *anyopaque, node: usize, bucket: []const u8, opts: types_mod.ListOpts, allocator: Allocator) anyerror!types_mod.ListPage {
        const dir = try dirOf(ctx, node);
        var idx = try list_index_mod.Index.init(allocator, dir);
        defer idx.deinit();
        return idx.list(allocator, bucket, opts);
    }
};

test "rebalance moves shards to their new owner when a 4th node joins" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [4]std.fs.Dir = undefined;
    for (0..4) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var mt: DiskMultiTransport = .{ .dirs = &dirs };
    const t = mt.transport();

    const k: u8 = 2;
    const m: u8 = 1;

    const nodes3 = [_][]const u8{ "n0", "n1", "n2" };
    var orch3 = try Orchestrator.init(std.testing.allocator, &nodes3, k, m, t);
    defer orch3.deinit();

    const bucket = "buk";
    const n_keys: usize = 50;
    var key_buf: [32]u8 = undefined;
    var results: [n_keys]orchestrator_mod.PutResult = undefined;

    // PUT 50 small objects under the 3-node view. Orchestrator.put only
    // scatters shard bytes — meta replication is a `ClusterRuntime`-layer
    // concern (see `writeMeta`) — so the test replicates meta to every
    // placement node itself, exactly like production does, since
    // `disk.forEachLocalKey` (the rebalance walk source) discovers keys via
    // local meta presence.
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        var data_buf: [64]u8 = undefined;
        const data = try std.fmt.bufPrint(&data_buf, "payload for object number {d}!!", .{i});
        results[i] = try orch3.put(bucket, key, data);
        try writeMetaToPlacement(&dirs, &orch3, bucket, key, results[i]);
    }

    // Shard count before rebalance: exactly (k+m) files per key across all dirs.
    const total_before = try countShardFiles(&dirs);
    try std.testing.expectEqual(n_keys * (k + m), total_before);

    // Node n3 joins -> 4-node view. Placement is now computed over 4 nodes.
    const nodes4 = [_][]const u8{ "n0", "n1", "n2", "n3" };
    var orch4 = try Orchestrator.init(std.testing.allocator, &nodes4, k, m, t);
    defer orch4.deinit();

    // Run one rebalance pass per simulated node (0..3). n3 starts empty so
    // its pass is a no-op; n0-n2 push any now-misplaced shard to n3.
    var total_moved: u64 = 0;
    for (0..4) |self_index| {
        const stats = try runOnceCore(std.testing.allocator, &orch4, t, dirs[self_index], self_index);
        total_moved += stats.moved;
        try std.testing.expectEqual(@as(u64, 0), stats.errors);
    }
    try std.testing.expect(total_moved > 0); // adding a node must move something

    // Every shard now lives exactly at its new-placement slot.
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        var place_buf: [3]usize = undefined;
        try orch4.placement(bucket, key, &place_buf);
        for (place_buf, 0..) |owner, shard_idx| {
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(shard_idx) };
            _ = try t.statShard(owner, sid); // must exist at the new owner
        }
    }

    // Total shard count is conserved (moved, not duplicated or dropped).
    const total_after = try countShardFiles(&dirs);
    try std.testing.expectEqual(total_before, total_after);

    // Every object is still readable through the new 4-node placement.
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        var expect_buf: [64]u8 = undefined;
        const expect = try std.fmt.bufPrint(&expect_buf, "payload for object number {d}!!", .{i});
        const out = try orch4.get(bucket, key, results[i].shard_size, results[i].original_size, std.testing.allocator);
        defer std.testing.allocator.free(out);
        try std.testing.expectEqualSlices(u8, expect, out);
    }
}

/// Test helper mirroring `ClusterRuntime.writeMeta`: replicate `result`'s
/// meta to every node in `orch`'s current placement for (bucket, key).
fn writeMetaToPlacement(dirs: []std.fs.Dir, orch: *Orchestrator, bucket: []const u8, key: []const u8, result: orchestrator_mod.PutResult) !void {
    const meta: runtime_mod.ObjectMeta = .{
        .shard_size = result.shard_size,
        .original_size = result.original_size,
        .etag = std.fmt.bytesToHex(result.md5, .lower),
        .content_type = "application/octet-stream",
        .last_modified = 0,
    };
    const json = try meta.toJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    const total = orch.codec.shardCount();
    var place_buf: [32]usize = undefined;
    const place = place_buf[0..total];
    try orch.placement(bucket, key, place);
    for (place) |owner| {
        try disk.putMeta(dirs[owner], bucket, key, json);
    }
}

fn countShardFiles(dirs: []std.fs.Dir) !usize {
    var total: usize = 0;
    for (dirs) |d| {
        var shards_dir = d.openDir(disk.shards_root, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        defer shards_dir.close();
        var walker = try shards_dir.walk(std.testing.allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.endsWith(u8, entry.path, ".shard")) total += 1;
        }
    }
    return total;
}

test "rebalance migrates every misplaced shard when a node holds several of one key" {
    // Regression: mid-rebalance a node can hold MORE than one shard of a
    // key (a peer's sweep pushed one here before ours ran). The old code
    // examined only one directory-iteration-ordered index per key, so
    // whether the second shard migrated depended on filesystem iteration
    // order (NTFS sorted = pass, ext4 hash order = flaky strand). This
    // test constructs that state directly, order-independently.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [2]std.fs.Dir = undefined;
    for (0..2) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var mt: DiskMultiTransport = .{ .dirs = &dirs };
    const t = mt.transport();

    const nodes = [_][]const u8{ "n0", "n1" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 1, 1, t);
    defer orch.deinit();

    // Find a key whose placement is [n0, n1] so shard0 belongs on n0 and
    // shard1 on n1 (deterministic search, HRW is stable).
    var key_buf: [32]u8 = undefined;
    var key: []const u8 = "";
    var place: [2]usize = undefined;
    for (0..64) |i| {
        key = try std.fmt.bufPrint(&key_buf, "seek-{d}", .{i});
        try orch.placement("buk", key, &place);
        if (place[0] == 0 and place[1] == 1) break;
    }
    try std.testing.expectEqual(@as(usize, 0), place[0]);
    try std.testing.expectEqual(@as(usize, 1), place[1]);

    // Node 0 holds BOTH shards; shard0 is correctly placed, shard1 is not.
    const chunk: usize = 8;
    const shard_bytes = "8bytes!!";
    try disk.putShard(dirs[0], "buk", key, 0, shard_bytes);
    try disk.putShard(dirs[0], "buk", key, 1, shard_bytes);
    const meta: runtime_mod.ObjectMeta = .{
        .shard_size = chunk,
        .original_size = chunk,
        .etag = "0123456789abcdef0123456789abcdef".*,
        .content_type = "application/octet-stream",
        .last_modified = 0,
    };
    const json = try meta.toJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try disk.putMeta(dirs[0], "buk", key, json);

    const stats = try runOnceCore(std.testing.allocator, &orch, t, dirs[0], 0);
    try std.testing.expectEqual(@as(u64, 1), stats.moved);
    try std.testing.expectEqual(@as(u64, 0), stats.errors);

    // shard1 now at n1, gone from n0; shard0 untouched at n0.
    try std.testing.expectEqual(@as(u64, chunk), try t.statShard(1, .{ .bucket = "buk", .key = key, .index = 1 }));
    try std.testing.expectError(error.ShardMissing, disk.statShard(dirs[0], "buk", key, 1));
    try std.testing.expectEqual(@as(u64, chunk), try disk.statShard(dirs[0], "buk", key, 0));
}

test "rebalance is a no-op when placement is unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [3]std.fs.Dir = undefined;
    for (0..3) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var mt: DiskMultiTransport = .{ .dirs = &dirs };
    const t = mt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 2, 1, t);
    defer orch.deinit();

    const result = try orch.put("buk", "stable-key", "unchanged placement, nothing to move");
    try writeMetaToPlacement(&dirs, &orch, "buk", "stable-key", result);

    for (0..3) |self_index| {
        const stats = try runOnceCore(std.testing.allocator, &orch, t, dirs[self_index], self_index);
        try std.testing.expectEqual(@as(u64, 0), stats.moved);
        try std.testing.expectEqual(@as(u64, 0), stats.errors);
    }
}

fn testMembershipConfig(peers: []const config_mod.Peer, self_idx: usize) config_mod.ClusterConfig {
    return .{
        .arena = undefined,
        .enabled = true,
        .node_id = peers[self_idx].id,
        .peers = peers,
        .self_index = self_idx,
        .ec_k = 1,
        .ec_m = 1,
        .cluster_secret = "0123456789abcdef",
        .connect_timeout_ms = 1000,
        .repl_targets_raw = "",
        .probe_interval_ms = 2000,
        .probe_fails_threshold = 3,
        .rebalance_interval_s = 300,
        .join = false,
    };
}

test "decommission: draining node's shards migrate off, node auto-removes, objects stay readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [3]std.fs.Dir = undefined;
    for (0..3) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var mt: DiskMultiTransport = .{ .dirs = &dirs };
    const t = mt.transport();

    // k=1, m=1: excluding one of the three nodes from write placement still
    // leaves enough (2) candidates, and a single surviving shard is enough
    // to reconstruct an object (full redundancy at k=1) — so reads must
    // keep working purely off the untouched shard even before/without the
    // read path ever consulting the migrated-to node.
    const nodes = [_][]const u8{ "n0", "n1", "n2" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 1, 1, t);
    defer orch.deinit();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
        .{ .id = "n2", .host = "h2", .port = 9002 },
    };
    const cfg = testMembershipConfig(&peers, 0);
    const mem = try membership_mod.Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();
    orch.membership = mem;

    const bucket = "buk";
    const n_keys: usize = 30;
    var key_buf: [32]u8 = undefined;
    var results: [n_keys]orchestrator_mod.PutResult = undefined;
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        var data_buf: [64]u8 = undefined;
        const data = try std.fmt.bufPrint(&data_buf, "decommission payload number {d}!!", .{i});
        results[i] = try orch.put(bucket, key, data);
        try writeMetaToPlacement(&dirs, &orch, bucket, key, results[i]);
    }

    // Sanity: n1 must actually hold shards before draining, else this test
    // would trivially pass without exercising the migration at all.
    var held_before: usize = 0;
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        if (try disk.localShardIndex(dirs[1], bucket, key)) |_| held_before += 1;
    }
    try std.testing.expect(held_before > 0);

    try mem.markDraining("n1");
    try std.testing.expectEqual(membership_mod.NodeState.draining, mem.stateOf(1));

    const stats = try runOnceDraining(std.testing.allocator, &orch, t, dirs[1], 1, mem);
    try std.testing.expectEqual(@as(u64, 0), stats.errors);
    try std.testing.expect(stats.moved > 0);

    // The draining node auto-promotes to removed once its own sweep leaves
    // it with zero local shards.
    try std.testing.expectEqual(membership_mod.NodeState.removed, mem.stateOf(1));
    try std.testing.expect(!(try disk.hasAnyLocalShard(dirs[1], std.testing.allocator)));

    // n1 is no longer a write-placement candidate.
    var id_buf: [8][]const u8 = undefined;
    var idx_buf: [8]usize = undefined;
    const ids = mem.placementIds(&id_buf, &idx_buf);
    for (ids) |id| try std.testing.expect(!std.mem.eql(u8, id, "n1"));

    // Every object put before the decommission is still readable.
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "key-{d}", .{i});
        var expect_buf: [64]u8 = undefined;
        const expect = try std.fmt.bufPrint(&expect_buf, "decommission payload number {d}!!", .{i});
        const out = try orch.get(bucket, key, results[i].shard_size, results[i].original_size, std.testing.allocator);
        defer std.testing.allocator.free(out);
        try std.testing.expectEqualSlices(u8, expect, out);
    }
}
