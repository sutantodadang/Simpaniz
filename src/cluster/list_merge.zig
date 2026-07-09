//! Cluster-wide ListObjectsV2: merges each usable node's local sorted
//! meta-key page (via `Transport.listMeta`) into one globally-correct,
//! paginated result — replacing the old "walk the local FS" cluster listing
//! path (which never actually saw remote nodes' keys at all).
//!
//! Transport-agnostic (works over the same `Transport` abstraction used for
//! shard/meta I/O), so `merge` is unit-testable with `DiskMultiTransport`-
//! style fakes exactly like the orchestrator/rebalance tests — no real
//! sockets needed.
//!
//! Pagination semantics are kept byte-identical to single-node
//! (`index.zig`'s `BucketIndex.list()`): `continuation_token` is INCLUSIVE,
//! `start_after` is EXCLUSIVE, delimiter/common-prefix collapsing and
//! max-keys truncation happen only AFTER the cross-node merge (each node's
//! own page is always fetched with `delimiter=""` — flat, sorted keys).
//!
//! Failure mode: if a usable node's `listMeta` errors twice in a row
//! (one retry), the WHOLE request fails (`error.ClusterListPeerFailed`)
//! rather than silently returning a partial listing.
const std = @import("std");
const Allocator = std.mem.Allocator;
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;
const membership_mod = @import("membership.zig");
const Membership = membership_mod.Membership;
const types = @import("../storage/types.zig");
const xml = @import("../xml.zig");

const NodeCursor = struct {
    buf: []xml.ObjectInfo = &.{},
    pos: usize = 0,
    /// True once this node has reported no more matching keys — never
    /// refetched again for the rest of this `merge` call.
    done: bool = false,
    /// True until this node's first fetch has happened; the first fetch
    /// passes the caller's own `continuation_token`/`start_after` through
    /// verbatim (preserving the client's inclusive/exclusive bound).
    /// Every subsequent fetch of the SAME node instead resumes via that
    /// node's own previously-returned `next_continuation_token`.
    first: bool = true,
    cont: []const u8 = "",
};

/// Merge sorted per-node pages into one cluster-wide `ListPage`. `t` is
/// queried for every node index `0..membership.count()` that
/// `membership.isUsable()` reports true for (draining included, down/
/// removed skipped) — this includes the local node, which callers route
/// through `Transport.listMeta` uniformly (no self special-casing needed
/// here; `HttpTransport`/test transports short-circuit self internally).
pub fn merge(t: Transport, membership: *Membership, allocator: Allocator, bucket: []const u8, opts: types.ListOpts) !types.ListPage {
    const total = membership.count();
    const nodes = try allocator.alloc(NodeCursor, total);
    const usable = try allocator.alloc(bool, total);
    for (0..total) |i| {
        usable[i] = membership.isUsable(i);
        nodes[i] = .{};
    }

    const max = if (opts.max_keys == 0 or opts.max_keys > 1000) 1000 else opts.max_keys;
    const per_fetch: usize = max + 1;

    var objects = std.ArrayList(xml.ObjectInfo){};
    var prefixes_set = std.StringArrayHashMap(void).init(allocator);
    var emitted: usize = 0;
    var truncated = false;
    var next_token: []const u8 = "";

    while (true) {
        // Ensure every active, non-exhausted node has a buffered head entry.
        for (nodes, 0..) |*nc, i| {
            if (!usable[i] or nc.done or nc.pos < nc.buf.len) continue;

            const node_opts: types.ListOpts = if (nc.first)
                .{ .prefix = opts.prefix, .delimiter = "", .continuation_token = opts.continuation_token, .start_after = opts.start_after, .max_keys = per_fetch }
            else
                .{ .prefix = opts.prefix, .delimiter = "", .continuation_token = nc.cont, .start_after = "", .max_keys = per_fetch };

            const page = t.listMeta(i, bucket, node_opts, allocator) catch blk: {
                break :blk t.listMeta(i, bucket, node_opts, allocator) catch |e| {
                    std.log.warn("cluster list: node={d} bucket={s} failed twice: {any}", .{ i, bucket, e });
                    return error.ClusterListPeerFailed;
                };
            };
            nc.first = false;
            nc.buf = page.objects;
            nc.pos = 0;
            nc.done = !page.is_truncated;
            nc.cont = page.next_continuation_token;
        }

        var min_key: ?[]const u8 = null;
        for (nodes, 0..) |nc, i| {
            if (!usable[i] or nc.pos >= nc.buf.len) continue;
            const k = nc.buf[nc.pos].key;
            if (min_key == null or std.mem.lessThan(u8, k, min_key.?)) min_key = k;
        }
        const mk = min_key orelse break; // every node exhausted

        // Dedupe: the same key can arrive from multiple nodes (meta is
        // replicated to every placement node) — advance all of them, keep
        // the entry with the lexicographically-greatest `last_modified`
        // (fixed-width ISO8601, so string order == chronological order):
        // "newest wins". Ties are identical objects anyway.
        var best: ?xml.ObjectInfo = null;
        for (nodes, 0..) |*nc, i| {
            if (!usable[i] or nc.pos >= nc.buf.len) continue;
            if (!std.mem.eql(u8, nc.buf[nc.pos].key, mk)) continue;
            const cand = nc.buf[nc.pos];
            nc.pos += 1;
            if (best == null or std.mem.lessThan(u8, best.?.last_modified, cand.last_modified)) best = cand;
        }
        const cand = best.?;

        // ── delimiter / common-prefix / max-keys bookkeeping — mirrors
        // `index.zig`'s `BucketIndex.list()` main loop exactly. ──
        if (opts.delimiter.len == 1 and opts.delimiter[0] == '/') {
            const suffix_start = opts.prefix.len;
            if (std.mem.indexOfScalarPos(u8, cand.key, suffix_start, '/')) |slash| {
                const cp = cand.key[0 .. slash + 1];
                if (!prefixes_set.contains(cp)) {
                    if (emitted >= max) {
                        truncated = true;
                        next_token = try allocator.dupe(u8, cand.key);
                        break;
                    }
                    const cp_owned = try allocator.dupe(u8, cp);
                    try prefixes_set.put(cp_owned, {});
                    emitted += 1;
                }
                continue;
            }
        }

        if (emitted >= max) {
            truncated = true;
            next_token = try allocator.dupe(u8, cand.key);
            break;
        }

        try objects.append(allocator, cand);
        emitted += 1;
    }

    const cps = prefixes_set.keys();
    const cps_owned = try allocator.alloc([]const u8, cps.len);
    for (cps, 0..) |k, i| cps_owned[i] = k;

    return .{
        .objects = try objects.toOwnedSlice(allocator),
        .common_prefixes = cps_owned,
        .is_truncated = truncated,
        .next_continuation_token = next_token,
    };
}

// ── Tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const disk = @import("disk_store.zig");
const config_mod = @import("config.zig");

/// Mirrors `rebalance.zig`'s private `DiskMultiTransport`: node `i`'s data
/// lives at `dirs[i]`, laid out exactly like the real on-disk `disk_store`
/// format, so `listMeta` can be served by a real `list_index.Index` — the
/// SAME production bootstrap/LSM-lite code path, no reinvented fixture.
const list_index_mod = @import("list_index.zig");

const TestTransport = struct {
    dirs: []std.fs.Dir,
    /// If set, `listMeta` fails for this node index (used to test the
    /// peer-failure -> whole-request-error path).
    fail_node: ?usize = null,

    fn transport(self: *TestTransport) Transport {
        return .{ .ctx = self, .vtable = &.{
            .putShard = notImpl,
            .getShard = notImplGet,
            .deleteShard = notImplDel,
            .putMeta = putMeta,
            .getMeta = notImplGetMeta,
            .deleteMeta = notImplDelMeta,
            .appendShardChunk = notImplAppend,
            .getShardRange = notImplRange,
            .statShard = notImplStat,
            .listMeta = listMetaFn,
        } };
    }

    fn notImpl(_: *anyopaque, _: usize, _: transport_mod.ShardId, _: []const u8) anyerror!void {
        return error.NotImplemented;
    }
    fn notImplGet(_: *anyopaque, _: usize, _: transport_mod.ShardId, _: Allocator) anyerror!?[]u8 {
        return error.NotImplemented;
    }
    fn notImplDel(_: *anyopaque, _: usize, _: transport_mod.ShardId) anyerror!void {
        return error.NotImplemented;
    }
    fn notImplAppend(_: *anyopaque, _: usize, _: transport_mod.ShardId, _: u64, _: []const u8) anyerror!void {
        return error.NotImplemented;
    }
    fn notImplRange(_: *anyopaque, _: usize, _: transport_mod.ShardId, _: u64, _: []u8) anyerror!usize {
        return error.NotImplemented;
    }
    fn notImplStat(_: *anyopaque, _: usize, _: transport_mod.ShardId) anyerror!u64 {
        return error.NotImplemented;
    }
    fn notImplGetMeta(_: *anyopaque, _: usize, _: []const u8, _: []const u8, _: Allocator) anyerror!?[]u8 {
        return error.NotImplemented;
    }
    fn notImplDelMeta(_: *anyopaque, _: usize, _: []const u8, _: []const u8) anyerror!void {
        return error.NotImplemented;
    }

    fn putMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void {
        const self: *TestTransport = @ptrCast(@alignCast(ctx));
        if (node >= self.dirs.len) return error.InvalidNode;
        return disk.putMeta(self.dirs[node], bucket, key, data);
    }

    fn listMetaFn(ctx: *anyopaque, node: usize, bucket: []const u8, opts: types.ListOpts, allocator: Allocator) anyerror!types.ListPage {
        const self: *TestTransport = @ptrCast(@alignCast(ctx));
        if (self.fail_node) |fn_idx| if (fn_idx == node) return error.SimulatedPeerFailure;
        if (node >= self.dirs.len) return error.InvalidNode;
        var idx = try list_index_mod.Index.init(allocator, self.dirs[node]);
        defer idx.deinit();
        return idx.list(allocator, bucket, opts);
    }
};

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

fn seedMeta(t: Transport, node: usize, bucket: []const u8, key: []const u8, size: u64, mtime_unix: i64, etag: [32]u8) !void {
    const meta: disk.ObjectMeta = .{ .shard_size = size, .original_size = size, .etag = etag, .content_type = "application/octet-stream", .last_modified = mtime_unix };
    const j = try meta.toJson(testing.allocator);
    defer testing.allocator.free(j);
    try t.putMeta(node, bucket, key, j);
}

fn etagFor(n: usize) [32]u8 {
    var e: [32]u8 = undefined;
    @memset(&e, '0');
    var buf: [8]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d:0>8}", .{n}) catch unreachable;
    @memcpy(e[24..32], s);
    return e;
}

test "merge: keys split across 3 nodes page correctly with no dupes/loss, small max-keys" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [3]std.fs.Dir = undefined;
    for (0..3) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var tt: TestTransport = .{ .dirs = &dirs };
    const t = tt.transport();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
        .{ .id = "n2", .host = "h2", .port = 9002 },
    };
    const cfg = testMembershipConfig(&peers, 0);
    const mem = try Membership.init(testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();

    // 50 keys, mixed prefixes, scattered round-robin across the 3 "nodes"
    // (simulating shard placement) — some keys duplicated on 2 nodes to
    // exercise the dedupe path.
    const bucket = "buk";
    var expected_keys = std.ArrayList([]u8){};
    defer {
        for (expected_keys.items) |k| testing.allocator.free(k);
        expected_keys.deinit(testing.allocator);
    }
    for (0..50) |i| {
        const prefix: []const u8 = if (i % 3 == 0) "a/" else if (i % 3 == 1) "b/" else "";
        const key = try std.fmt.allocPrint(testing.allocator, "{s}key-{d:0>3}", .{ prefix, i });
        try expected_keys.append(testing.allocator, key);
        const primary = i % 3;
        try seedMeta(t, primary, bucket, key, 10 + i, 1000 + @as(i64, @intCast(i)), etagFor(i));
        if (i % 5 == 0) {
            // Replicate onto a second node too (same content) to exercise dedupe.
            try seedMeta(t, (primary + 1) % 3, bucket, key, 10 + i, 1000 + @as(i64, @intCast(i)), etagFor(i));
        }
    }
    std.mem.sort([]u8, expected_keys.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    // Iterate all pages with a small max-keys, collect the union. `merge`'s
    // own working allocations (and the returned pages) use a scratch arena
    // here — production always calls `merge` with the per-request arena
    // (`HandlerContext.allocator`), so this mirrors real usage instead of
    // requiring `merge` to micro-manage frees for a batch/k-way-merge
    // algorithm that isn't a good fit for eager single-item frees (unlike
    // `index.zig`'s streaming single-node `list()`).
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const a = scratch.allocator();

    var got = std.ArrayList([]const u8){};
    defer got.deinit(testing.allocator);
    var cont: []const u8 = "";
    var pages: usize = 0;
    while (true) {
        pages += 1;
        try testing.expect(pages < 100); // guard against an infinite loop bug
        const page = try merge(t, mem, a, bucket, .{ .max_keys = 7, .continuation_token = cont });
        for (page.objects) |o| try got.append(testing.allocator, try testing.allocator.dupe(u8, o.key));
        if (!page.is_truncated) break;
        cont = page.next_continuation_token;
    }
    defer {
        for (got.items) |k| testing.allocator.free(k);
    }

    try testing.expectEqual(expected_keys.items.len, got.items.len);
    for (expected_keys.items, got.items) |exp, act| {
        try testing.expectEqualStrings(exp, act);
    }
    // Ascending, no dupes.
    for (1..got.items.len) |i| {
        try testing.expect(std.mem.lessThan(u8, got.items[i - 1], got.items[i]));
    }
}

test "merge: prefix + delimiter returns correct CommonPrefixes across nodes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [2]std.fs.Dir = undefined;
    for (0..2) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var tt: TestTransport = .{ .dirs = &dirs };
    const t = tt.transport();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testMembershipConfig(&peers, 0);
    const mem = try Membership.init(testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();

    const bucket = "buk";
    // "photos/2024/a.jpg", "photos/2024/b.jpg" (node0), "photos/2025/c.jpg" (node1), "docs/readme.txt" (node0)
    try seedMeta(t, 0, bucket, "photos/2024/a.jpg", 1, 1, etagFor(1));
    try seedMeta(t, 0, bucket, "photos/2024/b.jpg", 1, 2, etagFor(2));
    try seedMeta(t, 1, bucket, "photos/2025/c.jpg", 1, 3, etagFor(3));
    try seedMeta(t, 0, bucket, "docs/readme.txt", 1, 4, etagFor(4));

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const page = try merge(t, mem, scratch.allocator(), bucket, .{ .prefix = "photos/", .delimiter = "/", .max_keys = 1000 });

    try testing.expectEqual(@as(usize, 0), page.objects.len);
    try testing.expectEqual(@as(usize, 2), page.common_prefixes.len);
    try testing.expectEqualStrings("photos/2024/", page.common_prefixes[0]);
    try testing.expectEqualStrings("photos/2025/", page.common_prefixes[1]);
    try testing.expect(!page.is_truncated);
}

test "merge: a failing peer errors the whole request rather than returning a partial listing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [2]std.fs.Dir = undefined;
    for (0..2) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    var tt: TestTransport = .{ .dirs = &dirs, .fail_node = 1 };
    const t = tt.transport();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testMembershipConfig(&peers, 0);
    const mem = try Membership.init(testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();

    const bucket = "buk";
    try seedMeta(t, 0, bucket, "a", 1, 1, etagFor(1));

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    try testing.expectError(error.ClusterListPeerFailed, merge(t, mem, scratch.allocator(), bucket, .{ .max_keys = 10 }));
}

test "merge: a down node is skipped entirely (no error, no fetch)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dirs: [2]std.fs.Dir = undefined;
    for (0..2) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "node{d}", .{i});
        try tmp.dir.makePath(name);
        dirs[i] = try tmp.dir.openDir(name, .{ .iterate = true });
    }
    defer for (&dirs) |*d| d.close();

    // Node 1 would fail if queried — proves the down-skip actually avoids
    // calling it, not just tolerating its failure.
    var tt: TestTransport = .{ .dirs = &dirs, .fail_node = 1 };
    const t = tt.transport();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testMembershipConfig(&peers, 0);
    const mem = try Membership.init(testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();
    mem.recordProbeFailure(1);
    mem.recordProbeFailure(1);
    mem.recordProbeFailure(1);
    try testing.expect(!mem.isUsable(1));

    const bucket = "buk";
    try seedMeta(t, 0, bucket, "a", 1, 1, etagFor(1));

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    const page = try merge(t, mem, scratch.allocator(), bucket, .{ .max_keys = 10 });
    try testing.expectEqual(@as(usize, 1), page.objects.len);
    try testing.expectEqualStrings("a", page.objects[0].key);
}
