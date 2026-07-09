//! Distributed object orchestrator: RS encode + rendezvous-place + scatter on PUT,
//! gather + RS decode on GET, repair missing shards on heal.
//!
//! Stripe-streaming layout per (bucket, key):
//!   - The plaintext is split into fixed-size stripes of `k * chunk` bytes
//!     each (last stripe zero-padded). Each stripe is RS-encoded into
//!     `k + m` chunks of `chunk` bytes, which are *appended* to their
//!     respective shard files rather than buffering the whole object.
//!   - A shard file on a node is therefore the concatenation of that
//!     shard's per-stripe chunks: `n_stripes * chunk` bytes total.
//!   - `chunk` is chosen per-object: `default_chunk_size` (1 MiB) for large
//!     objects, or `ceil(original_size / k)` when the whole object fits in
//!     one stripe. `PutResult.shard_size` stores this per-stripe chunk size
//!     (same meta field as before — the on-disk meta format is unchanged).
//!   - Backward compatible with the old whole-object layout for free: an
//!     old object is exactly one stripe with `chunk = old shard_size`, so
//!     reading it with `n_stripes = ceil(original_size / (k*chunk))` (= 1)
//!     reproduces the old single-shard-file layout.
//!   - Shard `i` lives on node `placement[i]` chosen by HRW(node_id, "<bucket>/<key>").
//!
//! PUT/GET/heal only ever hold ~one stripe (a few MiB) in RAM at a time —
//! see `putStreaming`, `getRangeStreaming`, `heal`.
//!
//! Heal: for each shard slot, if the assigned node is missing it but at
//! least k other shards survive, reconstruct + push the missing one,
//! stripe by stripe.

const std = @import("std");
const Allocator = std.mem.Allocator;

const reed_solomon = @import("reed_solomon.zig");
const rendezvous = @import("rendezvous.zig");
const transport_mod = @import("transport.zig");
const membership_mod = @import("membership.zig");
const config_mod = @import("config.zig");

pub const ShardId = transport_mod.ShardId;
pub const Transport = transport_mod.Transport;
pub const Membership = membership_mod.Membership;

/// Upper bound on live node count consulted for placement. Matches
/// `reed_solomon.max_shards` / `rendezvous.max_picks * 4` (rendezvous'
/// internal scoring array caps at 128 candidate nodes).
const max_live_nodes: usize = 128;

pub const PutResult = struct {
    /// Per-stripe chunk size in bytes (NOT the total shard file length —
    /// that is `n_stripes * shard_size`).
    shard_size: usize,
    original_size: usize,
    md5: [16]u8 = std.mem.zeroes([16]u8),
};

/// Target per-stripe chunk size for large objects. A stripe holds
/// `k * default_chunk_size` plaintext bytes and is encoded into
/// `(k+m) * default_chunk_size` bytes on the wire/disk — the only buffer
/// PUT/GET/heal hold in RAM at a time.
pub const default_chunk_size: usize = 1024 * 1024;

pub const Orchestrator = struct {
    allocator: Allocator,
    codec: reed_solomon.Codec,
    nodes: []const []const u8,
    transport: Transport,
    /// When set, placement consults the live membership node list instead
    /// of the fixed `nodes` slice captured at `init` time — this is what
    /// makes shard placement react to nodes joining/leaving without a
    /// restart. `nodes` remains the fallback (and is what tests / the
    /// `LocalTransport` single-node path use, since they never attach a
    /// `Membership`).
    membership: ?*Membership = null,

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

    /// Current live node-id list: membership snapshot when attached,
    /// otherwise the fixed `nodes` slice from `init`. `buf` must outlive
    /// the returned slice's use (caller owns the backing storage).
    fn currentNodes(self: *const Orchestrator, buf: [][]const u8) []const []const u8 {
        if (self.membership) |mem| return mem.snapshotIds(buf);
        return self.nodes;
    }

    /// Compute placement: `out[i]` = node index that owns shard `i`. This is
    /// the READ path (`get`/`heal`/`getRangeStreaming`/`delete`): a
    /// `draining` node is deliberately still part of the candidate pool
    /// here, since it still physically holds its shards until the
    /// rebalance sweep migrates them off. See `writePlacement` for the
    /// write-side variant that excludes `draining`/`removed` nodes.
    pub fn placement(self: *const Orchestrator, bucket: []const u8, key: []const u8, out: []usize) !void {
        const total = self.codec.shardCount();
        if (out.len != total) return error.InvalidArgument;
        var kb: [1024]u8 = undefined;
        const pkey = try placementKey(&kb, bucket, key);
        var node_buf: [max_live_nodes][]const u8 = undefined;
        const nodes = self.currentNodes(&node_buf);
        const p = try rendezvous.pick(nodes, pkey, total);
        for (0..total) |i| out[i] = p.indices[i];
    }

    /// Node ids eligible for WRITE placement (membership snapshot minus
    /// `draining`/`removed`, or the fixed `nodes` fallback when no
    /// membership is attached — nothing to exclude there). `idx_buf[j]` is
    /// the TRUE node index of `id_buf[j]`, needed because rendezvous.pick's
    /// result indices are only local to whatever slice it was given.
    fn currentNodesForWrite(self: *const Orchestrator, id_buf: [][]const u8, idx_buf: []usize) []const []const u8 {
        if (self.membership) |mem| return mem.placementIds(id_buf, idx_buf);
        const n = @min(id_buf.len, self.nodes.len);
        for (0..n) |i| {
            id_buf[i] = self.nodes[i];
            idx_buf[i] = i;
        }
        return id_buf[0..n];
    }

    /// Compute placement for NEW writes and rebalance targets: like
    /// `placement`, but nodes marked `draining`/`removed` are excluded from
    /// the HRW candidate pool, so a decommissioning node is never (re-)
    /// chosen as an owner. Used by `put`/`putStreaming` and by
    /// `rebalance.migrateKeyCore`.
    pub fn writePlacement(self: *const Orchestrator, bucket: []const u8, key: []const u8, out: []usize) !void {
        const total = self.codec.shardCount();
        if (out.len != total) return error.InvalidArgument;
        var kb: [1024]u8 = undefined;
        const pkey = try placementKey(&kb, bucket, key);
        var id_buf: [max_live_nodes][]const u8 = undefined;
        var idx_buf: [max_live_nodes]usize = undefined;
        const nodes = self.currentNodesForWrite(&id_buf, &idx_buf);
        const p = try rendezvous.pick(nodes, pkey, total);
        for (0..total) |i| out[i] = idx_buf[p.indices[i]];
    }

    /// EC-encode `data` into k data + m parity shards and scatter them
    /// to their assigned nodes via the transport. Requires that all
    /// (k+m) nodes accept the writes.
    pub fn put(self: *Orchestrator, bucket: []const u8, key: []const u8, data: []const u8) !PutResult {
        var reader = std.Io.Reader.fixed(data);
        return self.putStreaming(bucket, key, &reader, data.len);
    }

    /// Streaming variant: read exactly `total_size` bytes from `reader`,
    /// one stripe (`k * chunk` plaintext bytes) at a time, encoding and
    /// appending each stripe's chunks to their shard files as they're
    /// produced. Only ~one stripe (`(k+m) * chunk` bytes) is ever held in
    /// RAM, regardless of object size.
    pub fn putFromReader(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        reader: *std.Io.Reader,
        total_size: usize,
    ) !PutResult {
        return self.putStreaming(bucket, key, reader, total_size);
    }

    /// Public streaming PUT entry point; always picks the chunk size from
    /// `default_chunk_size`. See `putStreamingChunk` for the chunk-override
    /// variant used by tests to exercise multi-stripe objects cheaply.
    pub fn putStreaming(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        reader: *std.Io.Reader,
        total_size: usize,
    ) !PutResult {
        return self.putStreamingChunk(bucket, key, reader, total_size, null);
    }

    /// Core streaming PUT. `chunk_override`, when set, replaces
    /// `default_chunk_size` as the base chunk size (tests use a small value
    /// so multi-stripe behavior can be exercised without allocating MiBs).
    fn putStreamingChunk(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        reader: *std.Io.Reader,
        total_size: usize,
        chunk_override: ?usize,
    ) !PutResult {
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;

        const base_chunk = chunk_override orelse default_chunk_size;
        const chunk: usize = if (total_size <= k * base_chunk)
            @max(1, (total_size + k - 1) / k)
        else
            base_chunk;

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.writePlacement(bucket, key, place[0..total]);

        const stripe_data_cap = k * chunk;
        const n_stripes: usize = if (total_size == 0) 1 else (total_size + stripe_data_cap - 1) / stripe_data_cap;

        const stripe_buf = try self.allocator.alloc(u8, total * chunk);
        defer self.allocator.free(stripe_buf);

        var data_slices: [reed_solomon.max_shards][]const u8 = undefined;
        var parity_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| data_slices[i] = stripe_buf[i * chunk ..][0..chunk];
        for (0..m) |i| parity_slices[i] = stripe_buf[(k + i) * chunk ..][0..chunk];

        var md5_ctx = std.crypto.hash.Md5.init(.{});

        errdefer {
            // Best-effort cleanup: drop whatever was already appended so a
            // failed PUT doesn't leave a partially-written object behind.
            for (0..total) |i| {
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
                self.transport.deleteShard(place[i], sid) catch {};
            }
        }

        for (0..n_stripes) |stripe_idx| {
            @memset(stripe_buf, 0);
            const stripe_start = stripe_idx * stripe_data_cap;
            const plaintext_len = if (stripe_start >= total_size) 0 else @min(total_size - stripe_start, stripe_data_cap);
            if (plaintext_len > 0) {
                try reader.readSliceAll(stripe_buf[0..plaintext_len]);
                md5_ctx.update(stripe_buf[0..plaintext_len]);
            }

            try self.codec.encode(data_slices[0..k], parity_slices[0..m]);

            for (0..total) |i| {
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
                try self.transport.appendShardChunk(place[i], sid, @intCast(stripe_idx), stripe_buf[i * chunk ..][0..chunk]);
            }
        }

        var md5_raw: [16]u8 = undefined;
        md5_ctx.final(&md5_raw);

        return .{ .shard_size = chunk, .original_size = total_size, .md5 = md5_raw };
    }

    /// Stream `[offset, offset + length)` of the plaintext object to
    /// `writer`, clamped to `original_size`. Holds only ~one stripe
    /// (`chunk` or `k * chunk` bytes, depending on path) in RAM regardless
    /// of object size. `chunk` must be the per-stripe chunk size recorded
    /// in `PutResult.shard_size` / `ObjectMeta.shard_size`.
    pub fn getRangeStreaming(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        chunk: usize,
        original_size: u64,
        offset: u64,
        length: u64,
        writer: *std.Io.Writer,
    ) !void {
        if (chunk == 0) return error.InvalidArgument;
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;
        const chunk64: u64 = @intCast(chunk);

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);

        const stripe_data_cap: u64 = @as(u64, k) * chunk64;
        const n_stripes: u64 = if (original_size == 0) 1 else (original_size + stripe_data_cap - 1) / stripe_data_cap;
        const expected_shard_len: u64 = n_stripes * chunk64;

        var available: [reed_solomon.max_shards]bool = .{false} ** reed_solomon.max_shards;
        var avail_count: usize = 0;
        for (0..total) |i| {
            // Down-node fast-skip: a node marked `down` by the membership
            // prober is treated as ShardMissing without a network round
            // trip, so a killed node doesn't stall reads waiting on a
            // connect/read timeout.
            if (self.membership) |mem| if (!mem.isUsable(place[i])) continue;
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const sz = self.transport.statShard(place[i], sid) catch continue;
            if (sz == expected_shard_len) {
                available[i] = true;
                avail_count += 1;
            }
        }
        if (avail_count < k) return error.NotEnoughShards;

        const end = @min(offset + length, original_size);
        if (offset >= end) return;

        var all_data_available = true;
        for (0..k) |i| {
            if (!available[i]) {
                all_data_available = false;
                break;
            }
        }

        if (all_data_available) {
            const buf = try self.allocator.alloc(u8, chunk);
            defer self.allocator.free(buf);

            var pos: u64 = offset;
            while (pos < end) {
                const stripe_idx: u64 = pos / stripe_data_cap;
                const in_stripe_off: u64 = pos - stripe_idx * stripe_data_cap;
                const data_shard: usize = @intCast(in_stripe_off / chunk64);
                const in_shard_off: u64 = in_stripe_off % chunk64;
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(data_shard) };
                const shard_file_off: u64 = stripe_idx * chunk64 + in_shard_off;
                const want: usize = @intCast(@min(chunk64 - in_shard_off, end - pos));
                const n = try self.transport.getShardRange(place[data_shard], sid, shard_file_off, buf[0..want]);
                if (n < want) return error.ShardMissing;
                try writer.writeAll(buf[0..want]);
                pos += @as(u64, @intCast(want));
            }
            return;
        }

        // Reconstruct path: pick any k available shards and rebuild the
        // missing data chunks stripe by stripe.
        var chosen: [reed_solomon.max_shards]usize = undefined;
        var n_chosen: usize = 0;
        for (0..total) |i| {
            if (available[i] and n_chosen < k) {
                chosen[n_chosen] = i;
                n_chosen += 1;
            }
        }

        const chosen_pool = try self.allocator.alloc(u8, k * chunk);
        defer self.allocator.free(chosen_pool);
        var chosen_bufs: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| chosen_bufs[i] = chosen_pool[i * chunk ..][0..chunk];

        const rec_pool = try self.allocator.alloc(u8, k * chunk);
        defer self.allocator.free(rec_pool);
        var rec_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| rec_slices[i] = rec_pool[i * chunk ..][0..chunk];

        const first_stripe: u64 = offset / stripe_data_cap;
        const last_stripe: u64 = (end - 1) / stripe_data_cap;

        var stripe_idx: u64 = first_stripe;
        while (stripe_idx <= last_stripe) : (stripe_idx += 1) {
            var present: [reed_solomon.max_shards]?[]const u8 = .{null} ** reed_solomon.max_shards;
            for (0..k) |ci| {
                const shard_i = chosen[ci];
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(shard_i) };
                const off: u64 = stripe_idx * chunk64;
                const n = try self.transport.getShardRange(place[shard_i], sid, off, chosen_bufs[ci]);
                if (n != chunk) return error.ShardMissing;
                present[shard_i] = chosen_bufs[ci];
            }

            try self.codec.reconstructData(present[0..total], rec_slices[0..k]);

            const stripe_start: u64 = stripe_idx * stripe_data_cap;
            const stripe_plain_len: u64 = @min(stripe_data_cap, original_size - stripe_start);
            const emit_start: u64 = @max(offset, stripe_start);
            const emit_end: u64 = @min(end, stripe_start + stripe_plain_len);
            if (emit_start >= emit_end) continue;

            var pos: u64 = emit_start;
            while (pos < emit_end) {
                const in_stripe_off: u64 = pos - stripe_start;
                const d: usize = @intCast(in_stripe_off / chunk64);
                const in_shard_off: u64 = in_stripe_off % chunk64;
                const in_shard_off_usize: usize = @intCast(in_shard_off);
                const want: usize = @intCast(@min(chunk64 - in_shard_off, emit_end - pos));
                const src: []const u8 = if (present[d]) |p| p else rec_slices[d];
                try writer.writeAll(src[in_shard_off_usize..][0..want]);
                pos += @as(u64, @intCast(want));
            }
        }
    }

    /// Gather any k surviving shards and reconstruct the original object.
    /// `original_size` is required to trim the padding. Thin wrapper over
    /// `getRangeStreaming` for callers that want the whole object in memory
    /// (e.g. CopyObject's local read side).
    pub fn get(
        self: *Orchestrator,
        bucket: []const u8,
        key: []const u8,
        shard_size: usize,
        original_size: usize,
        allocator: Allocator,
    ) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(allocator);
        errdefer aw.deinit();
        try self.getRangeStreaming(bucket, key, shard_size, original_size, 0, original_size, &aw.writer);
        return aw.toOwnedSlice();
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

    /// Heal report: check every shard slot's *file length* (stat only, no
    /// bulk fetch), reconstruct any missing/short shard stripe by stripe
    /// from survivors, and append the rebuilt chunks. Returns the number of
    /// shards that were repaired. `shard_size` is the per-stripe chunk size
    /// (same value stored in `PutResult.shard_size` / meta).
    pub fn heal(self: *Orchestrator, bucket: []const u8, key: []const u8, shard_size: usize) !usize {
        const k: usize = self.codec.k;
        const m: usize = self.codec.m;
        const total = k + m;
        if (shard_size == 0) return error.InvalidArgument;
        const shard_size64: u64 = @intCast(shard_size);

        var place: [reed_solomon.max_shards]usize = undefined;
        try self.placement(bucket, key, place[0..total]);

        // Stat every slot; the correct length is whatever the healthy
        // majority reports (n_stripes * shard_size). A mismatched or
        // missing length counts as "needs repair".
        var sizes: [reed_solomon.max_shards]?u64 = .{null} ** reed_solomon.max_shards;
        var expected_len: u64 = 0;
        for (0..total) |i| {
            // Same down-node fast-skip as getRangeStreaming — a down node's
            // slot is treated as "needs repair" without probing it.
            if (self.membership) |mem| if (!mem.isUsable(place[i])) continue;
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            const sz = self.transport.statShard(place[i], sid) catch continue;
            sizes[i] = sz;
            if (sz > expected_len) expected_len = sz;
        }
        if (expected_len == 0) return 0; // nothing on any node yet — nothing to heal
        if (expected_len % shard_size64 != 0) return error.InvalidArgument;
        const n_stripes: u64 = expected_len / shard_size64;

        var missing: [reed_solomon.max_shards]bool = .{false} ** reed_solomon.max_shards;
        var good_count: usize = 0;
        for (0..total) |i| {
            if (sizes[i] != null and sizes[i].? == expected_len) {
                good_count += 1;
            } else {
                missing[i] = true;
            }
        }
        if (good_count == total) return 0;
        if (good_count < k) return error.NotEnoughShards;

        // Clear out any short/corrupt files on the missing slots so the
        // per-stripe appendShardChunk seq check starts clean at seq 0.
        for (0..total) |i| {
            if (!missing[i]) continue;
            const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
            self.transport.deleteShard(place[i], sid) catch {};
        }

        var chosen: [reed_solomon.max_shards]usize = undefined;
        var n_chosen: usize = 0;
        for (0..total) |i| {
            if (!missing[i] and n_chosen < k) {
                chosen[n_chosen] = i;
                n_chosen += 1;
            }
        }

        const chosen_pool = try self.allocator.alloc(u8, k * shard_size);
        defer self.allocator.free(chosen_pool);
        var chosen_bufs: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| chosen_bufs[i] = chosen_pool[i * shard_size ..][0..shard_size];

        // Stripe-scratch: k data slices + m parity slices, one stripe wide.
        const stripe_pool = try self.allocator.alloc(u8, total * shard_size);
        defer self.allocator.free(stripe_pool);
        var data_slices: [reed_solomon.max_shards][]u8 = undefined;
        var parity_slices: [reed_solomon.max_shards][]u8 = undefined;
        for (0..k) |i| data_slices[i] = stripe_pool[i * shard_size ..][0..shard_size];
        for (0..m) |i| parity_slices[i] = stripe_pool[(k + i) * shard_size ..][0..shard_size];

        var stripe_idx: u64 = 0;
        while (stripe_idx < n_stripes) : (stripe_idx += 1) {
            var present: [reed_solomon.max_shards]?[]const u8 = .{null} ** reed_solomon.max_shards;
            const off: u64 = stripe_idx * shard_size64;
            for (0..k) |ci| {
                const shard_i = chosen[ci];
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(shard_i) };
                const n = try self.transport.getShardRange(place[shard_i], sid, off, chosen_bufs[ci]);
                if (n != shard_size) return error.ShardMissing;
                present[shard_i] = chosen_bufs[ci];
            }

            try self.codec.reconstructData(present[0..total], data_slices[0..k]);
            // Fill in any present data shards (codec leaves them untouched).
            for (0..k) |i| if (present[i]) |b| @memcpy(data_slices[i], b);

            var data_const: [reed_solomon.max_shards][]const u8 = undefined;
            for (0..k) |i| data_const[i] = data_slices[i];
            try self.codec.encode(data_const[0..k], parity_slices[0..m]);

            for (0..total) |i| {
                if (!missing[i]) continue;
                const sid: ShardId = .{ .bucket = bucket, .key = key, .index = @intCast(i) };
                const src = if (i < k) data_slices[i] else parity_slices[i - k];
                try self.transport.appendShardChunk(place[i], sid, stripe_idx, src);
            }
        }

        var repaired: usize = 0;
        for (0..total) |i| if (missing[i]) {
            repaired += 1;
        };
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

test "putStreamingChunk multi-stripe round-trip and ranged reads" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const k: usize = 4;
    const chunk_override: usize = 1024;
    const size: usize = (k * chunk_override * 7) / 2; // 3.5 stripes worth

    const data = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 197 +% 13);

    var reader = std.Io.Reader.fixed(data);
    const result = try orch.putStreamingChunk("buk", "multi", &reader, size, chunk_override);
    try std.testing.expectEqual(chunk_override, result.shard_size);
    try std.testing.expectEqual(size, result.original_size);

    // Whole-object GET.
    const out = try orch.get("buk", "multi", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);

    const stripe_data_cap = k * chunk_override;

    // Intra-stripe range (well inside stripe 0).
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        try orch.getRangeStreaming("buk", "multi", result.shard_size, result.original_size, 100, 200, &aw.writer);
        try std.testing.expectEqualSlices(u8, data[100..300], aw.written());
    }

    // Cross-stripe range (straddles the stripe boundary at k*chunk).
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        const start = stripe_data_cap - 50;
        const len = 200;
        try orch.getRangeStreaming("buk", "multi", result.shard_size, result.original_size, start, len, &aw.writer);
        try std.testing.expectEqualSlices(u8, data[start..][0..len], aw.written());
    }

    // Suffix range past the last full stripe.
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        const start = size - 300;
        try orch.getRangeStreaming("buk", "multi", result.shard_size, result.original_size, start, 10_000, &aw.writer);
        try std.testing.expectEqualSlices(u8, data[start..], aw.written());
    }
}

test "multi-stripe get tolerates losing m shards via reconstruction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const chunk_override: usize = 1024;
    const size: usize = 4 * chunk_override * 3 + 500; // spans 4 stripes

    const data = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 91 +% 7);

    var reader = std.Io.Reader.fixed(data);
    const result = try orch.putStreamingChunk("buk", "loss", &reader, size, chunk_override);

    var place: [6]usize = undefined;
    try orch.placement("buk", "loss", place[0..]);
    try t.deleteShard(place[0], .{ .bucket = "buk", .key = "loss", .index = 0 });
    try t.deleteShard(place[3], .{ .bucket = "buk", .key = "loss", .index = 3 });

    const out = try orch.get("buk", "loss", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    const start = 4 * chunk_override - 30;
    try orch.getRangeStreaming("buk", "loss", result.shard_size, result.original_size, start, 100, &aw.writer);
    try std.testing.expectEqualSlices(u8, data[start..][0..100], aw.written());
}

test "heal repairs a multi-stripe object" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const chunk_override: usize = 512;
    const size: usize = 4 * chunk_override * 3 + 100;

    const data = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 53 +% 3);

    var reader = std.Io.Reader.fixed(data);
    const result = try orch.putStreamingChunk("buk", "heal-multi", &reader, size, chunk_override);

    var place: [6]usize = undefined;
    try orch.placement("buk", "heal-multi", place[0..]);

    // Delete one shard, heal, and check the repaired file has the full
    // multi-stripe length back.
    try t.deleteShard(place[2], .{ .bucket = "buk", .key = "heal-multi", .index = 2 });
    const repaired1 = try orch.heal("buk", "heal-multi", result.shard_size);
    try std.testing.expectEqual(@as(usize, 1), repaired1);

    const n_stripes = (size + (4 * chunk_override) - 1) / (4 * chunk_override);
    const expect_len: u64 = @as(u64, n_stripes) * @as(u64, chunk_override);
    try std.testing.expectEqual(expect_len, try t.statShard(place[2], .{ .bucket = "buk", .key = "heal-multi", .index = 2 }));

    // Now drop m (2) OTHER shards; GET must still reconstruct correctly.
    try t.deleteShard(place[4], .{ .bucket = "buk", .key = "heal-multi", .index = 4 });
    try t.deleteShard(place[5], .{ .bucket = "buk", .key = "heal-multi", .index = 5 });

    const out = try orch.get("buk", "heal-multi", result.shard_size, result.original_size, std.testing.allocator);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "single-stripe small object round-trips via getRangeStreaming (old-format equivalence)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 6);
    const t = lt.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 4, 2, t);
    defer orch.deinit();

    const data = "small object, single stripe, old shard-file layout";
    const result = try orch.put("buk", "small", data);
    // A small object always fits in exactly one stripe.
    try std.testing.expectEqual(@as(usize, (data.len + 3) / 4), result.shard_size);

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try orch.getRangeStreaming("buk", "small", result.shard_size, result.original_size, 0, result.original_size, &aw.writer);
    try std.testing.expectEqualSlices(u8, data, aw.written());
}

fn testMembershipConfig(peers: []const config_mod.Peer, self_idx: usize, ec_k: u8, ec_m: u8) config_mod.ClusterConfig {
    return .{
        .arena = undefined,
        .enabled = true,
        .node_id = peers[self_idx].id,
        .peers = peers,
        .self_index = self_idx,
        .ec_k = ec_k,
        .ec_m = ec_m,
        .cluster_secret = "0123456789abcdef",
        .connect_timeout_ms = 1000,
        .repl_targets_raw = "",
        .probe_interval_ms = 2000,
        .probe_fails_threshold = 3,
        .rebalance_interval_s = 300,
        .join = false,
    };
}

test "placement reacts to membership.addNode; unchanged membership is stable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 1);
    const t = lt.transport();

    // 10 initial nodes with k+m=3: most keys' top-3 already excludes some
    // nodes, so a HRW property applies cleanly — adding an 11th node only
    // perturbs keys where it outranks the CURRENT weakest of the top-3
    // (expected ~3/11 of keys), unlike the degenerate "every node is
    // already selected" case where total == node count.
    var peer_ids_buf: [10][]const u8 = undefined;
    var peers_buf: [10]config_mod.Peer = undefined;
    var id_bufs: [10][8]u8 = undefined;
    for (0..10) |i| {
        const id = std.fmt.bufPrint(&id_bufs[i], "n{d}", .{i}) catch unreachable;
        peer_ids_buf[i] = id;
        peers_buf[i] = .{ .id = id, .host = "h", .port = @intCast(9000 + i) };
    }

    var orch = try Orchestrator.init(std.testing.allocator, &peer_ids_buf, 2, 1, t);
    defer orch.deinit();

    const cfg = testMembershipConfig(&peers_buf, 0, 2, 1);
    const mem = try membership_mod.Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();
    orch.membership = mem;

    const n_keys: usize = 200;
    var before: [n_keys][3]usize = undefined;
    var key_buf: [16]u8 = undefined;
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "k-{d}", .{i});
        try orch.placement("buk", key, &before[i]);
    }

    // Re-querying placement with unchanged membership must be identical.
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "k-{d}", .{i});
        var again: [3]usize = undefined;
        try orch.placement("buk", key, &again);
        try std.testing.expectEqualSlices(usize, &before[i], &again);
    }

    // An 11th node joins — placement must react without re-creating the
    // Orchestrator or its fixed `nodes` fallback slice.
    const added = try mem.addNode("n10", "h10", 9010);
    try std.testing.expect(added);

    var moved: usize = 0;
    for (0..n_keys) |i| {
        const key = try std.fmt.bufPrint(&key_buf, "k-{d}", .{i});
        var after: [3]usize = undefined;
        try orch.placement("buk", key, &after);
        if (!std.mem.eql(usize, &before[i], &after)) moved += 1;
    }
    // HRW perturbs a minority of keys when one node joins a healthy-sized
    // pool; assert a sane band rather than an exact figure to avoid flakiness.
    try std.testing.expect(moved > 0);
    try std.testing.expect(moved < (n_keys * 60) / 100);
}

/// Transport wrapper that counts `statShard` calls per node — used to prove
/// the down-node fast-skip in `getRangeStreaming` never touches a node
/// membership has marked `down`.
const CountingTransport = struct {
    inner: Transport,
    stat_counts: [8]usize = [_]usize{0} ** 8,

    fn transport(self: *CountingTransport) Transport {
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
        } };
    }
    fn put(ctx: *anyopaque, node: usize, sid: ShardId, data: []const u8) anyerror!void {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.putShard(node, sid, data);
    }
    fn get(ctx: *anyopaque, node: usize, sid: ShardId, allocator: Allocator) anyerror!?[]u8 {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.getShard(node, sid, allocator);
    }
    fn del(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!void {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.deleteShard(node, sid);
    }
    fn putMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.putMeta(node, bucket, key, data);
    }
    fn getMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) anyerror!?[]u8 {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.getMeta(node, bucket, key, allocator);
    }
    fn delMeta(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8) anyerror!void {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.deleteMeta(node, bucket, key);
    }
    fn appendChunk(ctx: *anyopaque, node: usize, sid: ShardId, seq: u64, data: []const u8) anyerror!void {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.appendShardChunk(node, sid, seq, data);
    }
    fn getRange(ctx: *anyopaque, node: usize, sid: ShardId, offset: u64, buf: []u8) anyerror!usize {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        return self.inner.getShardRange(node, sid, offset, buf);
    }
    fn statShardFn(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!u64 {
        const self: *CountingTransport = @ptrCast(@alignCast(ctx));
        self.stat_counts[node] += 1;
        return self.inner.statShard(node, sid);
    }
};

test "getRangeStreaming fast-skips a membership-down node without probing it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var lt = transport_mod.LocalTransport.init(tmp.dir, 3);
    var ct: CountingTransport = .{ .inner = lt.transport() };
    const t = ct.transport();

    const nodes = [_][]const u8{ "n0", "n1", "n2" };
    var orch = try Orchestrator.init(std.testing.allocator, &nodes, 2, 1, t);
    defer orch.deinit();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
        .{ .id = "n2", .host = "h2", .port = 9002 },
    };
    const cfg = testMembershipConfig(&peers, 0, 2, 1);
    const mem = try membership_mod.Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer mem.deinit();
    orch.membership = mem;

    const data = "down-node fast-skip payload, tolerable with m=1 lost";
    const result = try orch.put("buk", "k", data);

    var place: [3]usize = undefined;
    try orch.placement("buk", "k", &place);
    const down_node = place[0]; // mark whichever node owns shard 0 as down

    mem.recordProbeFailure(down_node);
    mem.recordProbeFailure(down_node);
    mem.recordProbeFailure(down_node); // 3 consecutive failures -> down
    try std.testing.expectEqual(membership_mod.NodeState.down, mem.stateOf(down_node));

    ct.stat_counts = [_]usize{0} ** 8;
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();
    try orch.getRangeStreaming("buk", "k", result.shard_size, result.original_size, 0, result.original_size, &aw.writer);
    try std.testing.expectEqualSlices(u8, data, aw.written());

    try std.testing.expectEqual(@as(usize, 0), ct.stat_counts[down_node]);
}
