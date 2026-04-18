//! Distributed object orchestrator: RS encode + rendezvous-place + scatter on PUT,
//! gather + RS decode on GET, repair missing shards on heal.
//!
//! Object layout per (bucket, key):
//!   - k+m shards of equal `shard_size = ceil(original_size / k)` bytes.
//!   - The last data shard is right-padded with zeros to `shard_size`.
//!   - Original byte length is stored alongside (caller-managed metadata).
//!   - Shard `i` lives on node `placement[i]` chosen by HRW(node_id, "<bucket>/<key>").
//!
//! Heal: for each shard slot, if the assigned node is missing it but at
//! least k other shards survive, reconstruct + push the missing one.

const std = @import("std");
const Allocator = std.mem.Allocator;

const reed_solomon = @import("reed_solomon.zig");
const rendezvous = @import("rendezvous.zig");
const transport_mod = @import("transport.zig");

pub const ShardId = transport_mod.ShardId;
pub const Transport = transport_mod.Transport;

pub const PutResult = struct {
    shard_size: usize,
    original_size: usize,
    md5: [16]u8 = std.mem.zeroes([16]u8),
};

pub const Orchestrator = struct {
    allocator: Allocator,
    codec: reed_solomon.Codec,
    nodes: []const []const u8,
    transport: Transport,

    pub fn init(
        allocator: Allocator,
        nodes: []const []const u8,
        k: u8,
        m: u8,
        transport: Transport,
    ) !Orchestrator {
        if (nodes.len < @as(usize, k) + @as(usize, m)) return error.NotEnoughNodes;
        return .{
            .allocator = allocator,
            .codec = try reed_solomon.Codec.init(allocator, k, m),
            .nodes = nodes,
            .transport = transport,
        };
    }

    pub fn deinit(self: *Orchestrator) void {
        self.codec.deinit();
    }

    fn placementKey(buf: []u8, bucket: []const u8, key: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ bucket, key });
    }

    /// Compute placement: `out[i]` = node index that owns shard `i`.
    pub fn placement(self: *const Orchestrator, bucket: []const u8, key: []const u8, out: []usize) !void {
        const total = self.codec.shardCount();
        if (out.len != total) return error.InvalidArgument;
        var kb: [1024]u8 = undefined;
        const pkey = try placementKey(&kb, bucket, key);
        const p = try rendezvous.pick(self.nodes, pkey, total);
        for (0..total) |i| out[i] = p.indices[i];
    }

    /// EC-encode `data` into k data + m parity shards and scatter them
    /// to their assigned nodes via the transport. Requires that all
    /// (k+m) nodes accept the writes.
    pub fn put(self: *Orchestrator, bucket: []const u8, key: []const u8, data: []const u8) !PutResult {
        return self.putInternal(bucket, key, data.len, .{ .bytes = data });
    }

    /// Streaming variant: read exactly `total_size` bytes from `reader` into
    /// the data region of the encode buffer, avoiding the caller having to
    /// pre-allocate a copy. Saves ~N bytes versus `put(bucket, key, body)`.
    pub fn putFromReader(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        reader: *std.Io.Reader,
        total_size: usize,
    ) !PutResult {
        return self.putInternal(bucket, key, total_size, .{ .reader = reader });
    }

    const PutSource = union(enum) {
        bytes: []const u8,
        reader: *std.Io.Reader,
    };

    fn putInternal(self: *Orchestrator, bucket: []const u8, key: []const u8, size: usize, src: PutSource) !PutResult {
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;

        const shard_size = (size + k - 1) / k;
        const ss = if (shard_size == 0) 1 else shard_size;

        const buf = try self.allocator.alloc(u8, ss * total);
        defer self.allocator.free(buf);
        @memset(buf, 0);

        if (size > 0) switch (src) {
            .bytes => |b| @memcpy(buf[0..size], b),
            .reader => |r| try r.readSliceAll(buf[0..size]),
        };

        var md5_raw: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(buf[0..size], &md5_raw, .{});

        var data_slices: [reed_solomon.max_shards][]const u8 = undefined;
        var parity_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| data_slices[i] = buf[i * ss ..][0..ss];
        for (0..m) |i| parity_slices[i] = buf[(k + i) * ss ..][0..ss];

        try self.codec.encode(data_slices[0..k], parity_slices[0..m]);

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);

        for (0..total) |i| {
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const shard_bytes = buf[i * ss ..][0..ss];
            try self.transport.putShard(place[i], sid, shard_bytes);
        }

        return .{ .shard_size = ss, .original_size = size, .md5 = md5_raw };
    }

    /// Gather any k surviving shards and reconstruct the original object.
    /// `original_size` is required to trim the padding.
    pub fn get(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        shard_size: usize,
        original_size: usize,
        allocator: Allocator,
    ) ![]u8 {
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);

        var fetched: [reed_solomon.max_shards]?[]u8 = .{null} ** reed_solomon.max_shards;
        defer for (fetched[0..total]) |maybe| {
            if (maybe) |b| self.allocator.free(b);
        };

        var have: usize = 0;
        for (0..total) |i| {
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const got = self.transport.getShard(place[i], sid, self.allocator) catch null;
            if (got) |b| {
                if (b.len != shard_size) {
                    self.allocator.free(b);
                    continue;
                }
                fetched[i] = b;
                have += 1;
                if (have >= total) break;
            }
        }
        if (have < k) return error.NotEnoughShards;

        // Build present[] for the codec; reconstruct missing data shards.
        var present: [reed_solomon.max_shards]?[]const u8 = undefined;
        for (0..total) |i| present[i] = if (fetched[i]) |b| @as([]const u8, b) else null;

        var rec_storage = try self.allocator.alloc(u8, k * shard_size);
        defer self.allocator.free(rec_storage);
        var rec_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| rec_slices[i] = rec_storage[i * shard_size ..][0..shard_size];

        try self.codec.reconstructData(present[0..total], rec_slices[0..k]);

        // Pull data shards into a flat buffer: prefer reconstructed for missing,
        // original for present.
        const out = try allocator.alloc(u8, original_size);
        errdefer allocator.free(out);
        var written: usize = 0;
        for (0..k) |i| {
            const remain = original_size - written;
            const take = @min(remain, shard_size);
            const src = if (fetched[i]) |b| b[0..take] else rec_slices[i][0..take];
            @memcpy(out[written..][0..take], src);
            written += take;
            if (written >= original_size) break;
        }
        return out;
    }

    /// Delete every shard for (bucket, key). Best-effort: ignores missing shards.
    pub fn delete(self: *Orchestrator, bucket: []const u8, key: []const u8) !void {
        const total = self.codec.shardCount();
        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);
        for (0..total) |i| {
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            self.transport.deleteShard(place[i], sid) catch {};
        }
    }

    /// Heal report: check every shard slot, reconstruct any missing
    /// shards from survivors, push them back. Returns the number of
    /// shards that were repaired.
    pub fn heal(self: *Orchestrator, bucket: []const u8, key: []const u8, shard_size: usize) !usize {
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);

        var fetched: [reed_solomon.max_shards]?[]u8 = .{null} ** reed_solomon.max_shards;
        defer for (fetched[0..total]) |maybe| {
            if (maybe) |b| self.allocator.free(b);
        };

        var have: usize = 0;
        var missing: [reed_solomon.max_shards]bool = .{false} ** reed_solomon.max_shards;
        for (0..total) |i| {
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const got = self.transport.getShard(place[i], sid, self.allocator) catch null;
            if (got) |b| {
                if (b.len != shard_size) {
                    self.allocator.free(b);
                    missing[i] = true;
                } else {
                    fetched[i] = b;
                    have += 1;
                }
            } else missing[i] = true;
        }
        if (have == total) return 0;
        if (have < k) return error.NotEnoughShards;

        // Reconstruct everything (data + parity) by re-encoding from k recovered data shards.
        var present: [reed_solomon.max_shards]?[]const u8 = undefined;
        for (0..total) |i| present[i] = if (fetched[i]) |b| @as([]const u8, b) else null;

        var data_buf = try self.allocator.alloc(u8, k * shard_size);
        defer self.allocator.free(data_buf);
        var data_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| data_slices[i] = data_buf[i * shard_size ..][0..shard_size];
        try self.codec.reconstructData(present[0..total], data_slices[0..k]);

        // Fill in any present data shards (codec leaves them untouched).
        for (0..k) |i| if (fetched[i]) |b| @memcpy(data_slices[i], b);

        // Re-encode parity.
        var parity_buf = try self.allocator.alloc(u8, m * shard_size);
        defer self.allocator.free(parity_buf);
        var parity_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..m) |i| parity_slices[i] = parity_buf[i * shard_size ..][0..shard_size];
        var data_const: [reed_solomon.max_shards][]const u8 = undefined;
        for (0..k) |i| data_const[i] = data_slices[i];
        try self.codec.encode(data_const[0..k], parity_slices[0..m]);

        var repaired: usize = 0;
        for (0..total) |i| {
            if (!missing[i]) continue;
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const src = if (i < k) data_slices[i] else parity_slices[i - k];
            try self.transport.putShard(place[i], sid, src);
            repaired += 1;
        }
        return repaired;
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "put + get round-trips object" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const data = "Hello, distributed Simpaniz! 0123456789ABCDEF" ** 7;
    const result = try orch.put("buk", "key1", data);

    const out = try orch.get("buk", "key1", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "get tolerates losing m shards" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const data = "fault-tolerant payload bytes here";
    const result = try orch.put("b", "k", data);

    // Drop 2 random-ish shards (slot 0 and slot 3).
    var place: [6]usize = undefined;
    try orch.placement("b", "k", place[0..]);
    try t.deleteShard(place[0], .{ .bucket = "b", .key = "k", .index = 0 });
    try t.deleteShard(place[3], .{ .bucket = "b", .key = "k", .index = 3 });

    const out = try orch.get("b", "k", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "heal repairs missing shards" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const data = "heal me up scotty" ** 4;
    const result = try orch.put("b", "k", data);

    var place: [6]usize = undefined;
    try orch.placement("b", "k", place[0..]);
    try t.deleteShard(place[1], .{ .bucket = "b", .key = "k", .index = 1 });
    try t.deleteShard(place[4], .{ .bucket = "b", .key = "k", .index = 4 });

    const repaired = try orch.heal("b", "k", result.shard_size);
    try std.testing.expectEqual(@as(usize, 2), repaired);

    // After heal, all six shards must be present and a fresh GET still works.
    const after_heal = try orch.heal("b", "k", result.shard_size);
    try std.testing.expectEqual(@as(usize, 0), after_heal);

    const out = try orch.get("b", "k", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "get fails when more than m shards lost" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const data = "doomed without quorum";
    const result = try orch.put("b", "k", data);

    var place: [6]usize = undefined;
    try orch.placement("b", "k", place[0..]);
    // Lose 3 shards (m=2 — should fail).
    for (0..3) |i| try t.deleteShard(place[i], .{ .bucket = "b", .key = "k", .index = @intCast(i) });

    try std.testing.expectError(error.NotEnoughShards, orch.get("b", "k", result.shard_size, result.original_size, std.testing.allocator));
}

test "delete removes every shard" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const result = try orch.put("b", "k", "bye");
    try orch.delete("b", "k");
    try std.testing.expectError(error.NotEnoughShards, orch.get("b", "k", result.shard_size, result.original_size, std.testing.allocator));
}
