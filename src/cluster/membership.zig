//! Cluster membership: active health probing + minimal gossip + dynamic
//! node join.
//!
//! This is "SWIM-lite": nodes are actively probed on an interval and their
//! liveness state (alive/suspect/down) is derived purely from LOCAL probe
//! results (no distributed failure-detector voting). The only thing that
//! travels over gossip is the NODE LIST itself — each probe response
//! piggybacks the responder's membership view (`snapshotJson`), and any
//! node id we don't already know is adopted via `addNode`. We deliberately
//! do NOT adopt a peer's opinion of a third node's alive/suspect/down state
//! — that stays locally observed, which keeps the state machine simple and
//! avoids stale-gossip flapping. This is a documented simplification versus
//! full SWIM.
//!
//! Membership is index-stable and append-only: `nodes[i]` never changes
//! identity and entries are never removed from the in-memory array (a
//! `down` node just stays `down` forever, or comes back `alive` on the next
//! successful probe). This matters because shard placement indices
//! (`rendezvous.pick` over node ids) must stay valid as long as the
//! underlying id string is stable, and `Orchestrator.placement` reads the
//! current node-id list through `Membership.snapshotIds` on every call.
//!
//! Decommission (`draining` -> `removed`) is layered on top without
//! breaking that invariant: a `draining`/`removed` node's array slot never
//! moves, it's just excluded from `Orchestrator.writePlacement`'s HRW
//! candidate pool (see `placementIds`) so new writes and rebalance targets
//! stop landing on it, while `placement` (the read path) is untouched so
//! in-flight reads still find shards that haven't migrated off it yet.
//! `draining`/`removed` are sticky: ordinary probe success/failure never
//! flips them back to alive/suspect/down (see `recordProbeSuccess`/
//! `recordProbeFailure`), and they gossip-propagate with
//! `removed` > `draining` precedence over any other opinion (see
//! `mergeGossip`).
//!
//! Newly joined nodes (beyond the statically configured `config.peers`)
//! are persisted to `<data_dir>/.simpaniz-peers.json` so a restart doesn't
//! forget them.
const std = @import("std");
const Allocator = std.mem.Allocator;
const config_mod = @import("config.zig");
const ClusterConfig = config_mod.ClusterConfig;

pub const NodeState = enum { alive, suspect, down, draining, removed };

pub const NodeInfo = struct {
    id: []const u8, // owned
    host: []const u8, // owned
    port: u16,
    state: NodeState,
    incarnation: u64,
    last_change_ms: i64,
    is_self: bool,
    fail_count: u32 = 0,
};

const overlay_filename = ".simpaniz-peers.json";

/// Ping callback: probe node `node_idx` and return the peer's membership
/// snapshot JSON body (caller frees with `allocator`). Kept as a vtable-ish
/// callback so `Membership` doesn't need to depend on `HttpTransport`
/// (avoids an import cycle and keeps the prober unit-testable).
pub const Pinger = struct {
    ctx: *anyopaque,
    pingFn: *const fn (ctx: *anyopaque, node_idx: usize, allocator: Allocator) anyerror![]u8,

    fn ping(self: Pinger, node_idx: usize, allocator: Allocator) ![]u8 {
        return self.pingFn(self.ctx, node_idx, allocator);
    }
};

pub const Membership = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    nodes: std.ArrayList(NodeInfo),
    /// Bumped on every state CHANGE (join or alive/suspect/down transition).
    generation: std.atomic.Value(u64) = .{ .raw = 0 },
    self_index: usize,
    data_dir: std.fs.Dir,
    /// Number of nodes present at boot from `config.peers` — everything
    /// beyond this index is a dynamically joined node and gets persisted
    /// to the overlay file.
    initial_count: usize,
    probe_fails_threshold: u32,
    probe_interval_ms: u32,

    pinger: ?Pinger = null,
    worker: ?std.Thread = null,
    running: std.atomic.Value(bool) = .{ .raw = false },

    pub fn init(allocator: Allocator, config: *const ClusterConfig, data_dir: std.fs.Dir) !*Membership {
        const m = try allocator.create(Membership);
        errdefer allocator.destroy(m);
        m.* = .{
            .allocator = allocator,
            .nodes = .{},
            .self_index = config.self_index,
            .data_dir = data_dir,
            .initial_count = config.peers.len,
            .probe_fails_threshold = config.probe_fails_threshold,
            .probe_interval_ms = config.probe_interval_ms,
        };
        errdefer m.nodes.deinit(allocator);
        for (config.peers, 0..) |p, i| {
            const id_owned = try allocator.dupe(u8, p.id);
            errdefer allocator.free(id_owned);
            const host_owned = try allocator.dupe(u8, p.host);
            errdefer allocator.free(host_owned);
            try m.nodes.append(allocator, .{
                .id = id_owned,
                .host = host_owned,
                .port = p.port,
                .state = .alive,
                .incarnation = 0,
                .last_change_ms = std.time.milliTimestamp(),
                .is_self = (i == config.self_index),
            });
        }
        m.loadOverlay() catch |e| {
            std.log.warn("membership: overlay load failed: {any}", .{e});
        };
        return m;
    }

    pub fn deinit(self: *Membership) void {
        self.shutdown();
        for (self.nodes.items) |n| {
            self.allocator.free(n.id);
            self.allocator.free(n.host);
        }
        self.nodes.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ── Prober lifecycle ────────────────────────────────────────────────

    pub fn start(self: *Membership, pinger: Pinger) !void {
        if (self.worker != null) return;
        self.pinger = pinger;
        self.running.store(true, .seq_cst);
        self.worker = try std.Thread.spawn(.{}, proberLoop, .{self});
    }

    /// Signal the prober to stop and join it. Safe to call more than once.
    pub fn shutdown(self: *Membership) void {
        self.running.store(false, .seq_cst);
        if (self.worker) |w| {
            w.join();
            self.worker = null;
        }
    }

    fn proberLoop(self: *Membership) void {
        while (self.running.load(.seq_cst)) {
            const interval_ms = @max(self.probe_interval_ms, 50);
            std.Thread.sleep(@as(u64, interval_ms) * std.time.ns_per_ms);
            if (!self.running.load(.seq_cst)) break;
            self.probeAll();
        }
    }

    fn probeAll(self: *Membership) void {
        const pinger = self.pinger orelse return;
        const n = self.count();
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (i == self.self_index) continue;
            const body = pinger.ping(i, self.allocator) catch {
                self.recordProbeFailure(i);
                continue;
            };
            defer self.allocator.free(body);
            self.recordProbeSuccess(i);
            self.mergeGossip(body) catch |e| {
                std.log.debug("membership: gossip merge failed: {any}", .{e});
            };
        }
    }

    // ── Queries ─────────────────────────────────────────────────────────

    pub fn count(self: *Membership) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.nodes.items.len;
    }

    pub fn isUsable(self: *Membership, idx: usize) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return false;
        return switch (self.nodes.items[idx].state) {
            .down, .removed => false,
            .alive, .suspect, .draining => true,
        };
    }

    /// Id at index `idx`, or null if out of range. Independent of the
    /// `self_index` this `Membership` was constructed with — used by the
    /// rebalance sweep to resolve "my id" for a caller-chosen simulated
    /// self-index (tests drive several simulated nodes through one shared
    /// `Membership`).
    pub fn idAt(self: *Membership, idx: usize) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return null;
        return self.nodes.items[idx].id;
    }

    /// Node ids eligible for WRITE placement: like `snapshotIds`, but
    /// `draining`/`removed` nodes are excluded. `idx_buf[j]` is the TRUE
    /// (index-stable) membership index of `id_buf[j]`, so a caller that
    /// runs rendezvous hashing over the returned slice can translate the
    /// local result index back to a real node index.
    pub fn placementIds(self: *Membership, id_buf: [][]const u8, idx_buf: []usize) []const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var n: usize = 0;
        for (self.nodes.items, 0..) |node, i| {
            if (node.state == .draining or node.state == .removed) continue;
            if (n >= id_buf.len) break;
            id_buf[n] = node.id;
            idx_buf[n] = i;
            n += 1;
        }
        return id_buf[0..n];
    }

    pub fn stateOf(self: *Membership, idx: usize) NodeState {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return .down;
        return self.nodes.items[idx].state;
    }

    pub const HostPort = struct { host: []const u8, port: u16 };

    /// Resolve host:port for `idx`. The returned `host` slice points at
    /// storage owned by `Membership` (stable for process lifetime — ids
    /// and hosts are append-only and never freed until `deinit`).
    pub fn hostPortOf(self: *Membership, idx: usize) ?HostPort {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return null;
        return .{ .host = self.nodes.items[idx].host, .port = self.nodes.items[idx].port };
    }

    /// Copy up to `buf.len` current node ids into `buf` and return the
    /// filled prefix. Used by `Orchestrator.placement` as the live node
    /// list for rendezvous hashing.
    pub fn snapshotIds(self: *Membership, buf: [][]const u8) []const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = @min(buf.len, self.nodes.items.len);
        for (0..n) |i| buf[i] = self.nodes.items[i].id;
        return buf[0..n];
    }

    /// Allocate-and-copy variant of `snapshotIds` for callers that need an
    /// owned slice (e.g. tests, rebalance sweeps).
    pub fn nodeIds(self: *Membership, alloc: Allocator) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = try alloc.alloc([]const u8, self.nodes.items.len);
        for (self.nodes.items, 0..) |n, i| out[i] = n.id;
        return out;
    }

    pub fn snapshotJson(self: *Membership, alloc: Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var buf: std.ArrayList(u8) = .{};
        errdefer buf.deinit(alloc);
        try buf.appendSlice(alloc, "[");
        for (self.nodes.items, 0..) |n, i| {
            if (i > 0) try buf.appendSlice(alloc, ",");
            const state_str: []const u8 = switch (n.state) {
                .alive => "alive",
                .suspect => "suspect",
                .down => "down",
                .draining => "draining",
                .removed => "removed",
            };
            const entry = try std.fmt.allocPrint(
                alloc,
                "{{\"id\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"state\":\"{s}\",\"incarnation\":{d}}}",
                .{ n.id, n.host, n.port, state_str, n.incarnation },
            );
            defer alloc.free(entry);
            try buf.appendSlice(alloc, entry);
        }
        try buf.appendSlice(alloc, "]");
        return buf.toOwnedSlice(alloc);
    }

    // ── Mutation ────────────────────────────────────────────────────────

    pub fn recordProbeSuccess(self: *Membership, idx: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return;
        const n = &self.nodes.items[idx];
        // draining/removed are sticky admin decisions — an ordinary probe
        // success must never flip a decommissioning node back to alive.
        if (n.state == .draining or n.state == .removed) return;
        n.fail_count = 0;
        if (n.state != .alive) {
            n.state = .alive;
            n.incarnation += 1;
            n.last_change_ms = std.time.milliTimestamp();
            _ = self.generation.fetchAdd(1, .monotonic);
            std.log.info("membership: node {s} -> alive", .{n.id});
        }
    }

    pub fn recordProbeFailure(self: *Membership, idx: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (idx >= self.nodes.items.len) return;
        const n = &self.nodes.items[idx];
        if (n.state == .draining or n.state == .removed) return;
        n.fail_count +|= 1;
        const new_state: NodeState = if (n.fail_count >= self.probe_fails_threshold) .down else .suspect;
        if (new_state != n.state) {
            n.state = new_state;
            n.incarnation += 1;
            n.last_change_ms = std.time.milliTimestamp();
            _ = self.generation.fetchAdd(1, .monotonic);
            std.log.warn("membership: node {s} -> {s}", .{ n.id, @tagName(new_state) });
        }
    }

    /// Mark node `id` `draining`: an admin-initiated decommission. The node
    /// stays a valid READ source (`placement`/`isUsable`) until the
    /// rebalance sweep migrates its shards elsewhere, but is immediately
    /// excluded from `Orchestrator.writePlacement`'s HRW candidate pool, so
    /// new writes and rebalance targets stop landing on it. Sticky: a
    /// `removed` node is never downgraded back to `draining`. Idempotent.
    /// Returns `error.UnknownNode` if `id` isn't a known node.
    pub fn markDraining(self: *Membership, id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |*n| {
            if (!std.mem.eql(u8, n.id, id)) continue;
            if (n.state == .removed or n.state == .draining) return; // terminal/idempotent
            n.state = .draining;
            n.incarnation += 1;
            n.last_change_ms = std.time.milliTimestamp();
            _ = self.generation.fetchAdd(1, .monotonic);
            std.log.info("membership: node {s} -> draining", .{n.id});
            self.persistOverlayLocked();
            return;
        }
        return error.UnknownNode;
    }

    /// Mark node `id` `removed`: the terminal state of a decommission.
    /// Dropped from the persisted peer overlay on the next persist (see
    /// `persistOverlayLocked`). Called by the rebalance sweep once a
    /// draining node has migrated away every locally-held shard. Idempotent.
    /// Returns `error.UnknownNode` if `id` isn't a known node.
    pub fn markRemoved(self: *Membership, id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |*n| {
            if (!std.mem.eql(u8, n.id, id)) continue;
            if (n.state == .removed) return; // idempotent
            n.state = .removed;
            n.incarnation += 1;
            n.last_change_ms = std.time.milliTimestamp();
            _ = self.generation.fetchAdd(1, .monotonic);
            std.log.info("membership: node {s} -> removed", .{n.id});
            self.persistOverlayLocked();
            return;
        }
        return error.UnknownNode;
    }

    /// Add a new node if `id` is unknown. Returns `true` if it was added.
    /// Persists the joined-node overlay file on success.
    pub fn addNode(self: *Membership, id: []const u8, host: []const u8, port: u16) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |n| {
            if (std.mem.eql(u8, n.id, id)) return false;
        }
        const id_owned = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_owned);
        const host_owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(host_owned);
        try self.nodes.append(self.allocator, .{
            .id = id_owned,
            .host = host_owned,
            .port = port,
            .state = .alive,
            .incarnation = 0,
            .last_change_ms = std.time.milliTimestamp(),
            .is_self = false,
        });
        _ = self.generation.fetchAdd(1, .monotonic);
        std.log.info("membership: node {s} joined ({s}:{d})", .{ id, host, port });
        self.persistOverlayLocked();
        return true;
    }

    /// Minimal SWIM-lite gossip merge: adopt any node id present in `json`
    /// (an array of `{"id","host","port",...}` objects, i.e. the shape
    /// produced by `snapshotJson`) that we don't already know about. See
    /// the module doc comment for why we don't adopt remote alive/suspect/
    /// down opinions — `draining`/`removed` are the one exception: those
    /// ARE adopted (see `adoptGossipState`) so an admin-initiated
    /// decommission propagates cluster-wide without every node needing to
    /// be hit directly.
    pub fn mergeGossip(self: *Membership, json: []const u8) !void {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, json, .{});
        defer parsed.deinit();
        if (parsed.value != .array) return error.BadGossip;
        for (parsed.value.array.items) |item| {
            if (item != .object) continue;
            const obj = item.object;
            const id_v = obj.get("id") orelse continue;
            const host_v = obj.get("host") orelse continue;
            const port_v = obj.get("port") orelse continue;
            if (id_v != .string or host_v != .string) continue;
            const port: u16 = switch (port_v) {
                .integer => |v| if (v >= 0 and v <= std.math.maxInt(u16)) @intCast(v) else continue,
                else => continue,
            };
            _ = self.addNode(id_v.string, host_v.string, port) catch |e| {
                std.log.debug("membership: gossip addNode failed: {any}", .{e});
            };
            if (obj.get("state")) |state_v| {
                if (state_v == .string) {
                    if (parseStateStr(state_v.string)) |incoming| {
                        if (incoming == .draining or incoming == .removed) {
                            self.adoptGossipState(id_v.string, incoming);
                        }
                    }
                }
            }
        }
    }

    /// Adopt a `draining`/`removed` opinion learned via gossip for a known
    /// node. `removed` beats `draining` beats anything already set; a
    /// `removed` node is never un-removed.
    fn adoptGossipState(self: *Membership, id: []const u8, incoming: NodeState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |*n| {
            if (!std.mem.eql(u8, n.id, id)) continue;
            if (n.state == .removed) return; // terminal
            if (incoming == .removed) {
                n.state = .removed;
            } else if (incoming == .draining and n.state != .draining) {
                n.state = .draining;
            } else {
                return; // no change (already draining)
            }
            n.incarnation += 1;
            n.last_change_ms = std.time.milliTimestamp();
            _ = self.generation.fetchAdd(1, .monotonic);
            std.log.info("membership: node {s} -> {s} (via gossip)", .{ n.id, @tagName(n.state) });
            self.persistOverlayLocked();
            return;
        }
    }

    // ── Persistence (joined-node overlay) ──────────────────────────────

    fn loadOverlay(self: *Membership) !void {
        var f = self.data_dir.openFile(overlay_filename, .{}) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return e,
        };
        defer f.close();
        const stat = try f.stat();
        if (stat.size == 0) return;
        const buf = try self.allocator.alloc(u8, stat.size);
        defer self.allocator.free(buf);
        const n = try f.readAll(buf);
        if (n != stat.size) return error.ShortRead;

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, buf[0..n], .{});
        defer parsed.deinit();
        if (parsed.value != .array) return;
        for (parsed.value.array.items) |item| {
            if (item != .object) continue;
            const obj = item.object;
            const id_v = obj.get("id") orelse continue;
            const host_v = obj.get("host") orelse continue;
            const port_v = obj.get("port") orelse continue;
            if (id_v != .string or host_v != .string) continue;
            const port: u16 = switch (port_v) {
                .integer => |v| if (v >= 0 and v <= std.math.maxInt(u16)) @intCast(v) else continue,
                else => continue,
            };
            var exists = false;
            for (self.nodes.items) |nd| {
                if (std.mem.eql(u8, nd.id, id_v.string)) {
                    exists = true;
                    break;
                }
            }
            if (exists) continue;
            // `draining` is the only non-default state ever persisted (see
            // `persistOverlayLocked` — `removed` nodes are dropped from the
            // file entirely, never written), so that's the only one to
            // restore here; anything else (or missing) defaults to `alive`.
            var state: NodeState = .alive;
            if (obj.get("state")) |sv| {
                if (sv == .string and std.mem.eql(u8, sv.string, "draining")) state = .draining;
            }
            const id_owned = try self.allocator.dupe(u8, id_v.string);
            errdefer self.allocator.free(id_owned);
            const host_owned = try self.allocator.dupe(u8, host_v.string);
            errdefer self.allocator.free(host_owned);
            try self.nodes.append(self.allocator, .{
                .id = id_owned,
                .host = host_owned,
                .port = port,
                .state = state,
                .incarnation = 0,
                .last_change_ms = std.time.milliTimestamp(),
                .is_self = false,
            });
        }
    }

    /// Must be called with `self.mutex` held. Best-effort: logs and
    /// swallows errors rather than propagating (persistence failing must
    /// never break the in-memory join). `removed` nodes are dropped from
    /// the file entirely (decommission is meant to forget them); `draining`
    /// is persisted with an explicit `"state"` field so a restart doesn't
    /// silently un-drain a node mid-decommission.
    fn persistOverlayLocked(self: *Membership) void {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(self.allocator);
        buf.appendSlice(self.allocator, "[") catch return;
        var first = true;
        for (self.nodes.items[self.initial_count..]) |n| {
            if (n.state == .removed) continue;
            if (!first) buf.appendSlice(self.allocator, ",") catch return;
            first = false;
            const entry = if (n.state == .draining)
                std.fmt.allocPrint(
                    self.allocator,
                    "{{\"id\":\"{s}\",\"host\":\"{s}\",\"port\":{d},\"state\":\"draining\"}}",
                    .{ n.id, n.host, n.port },
                ) catch return
            else
                std.fmt.allocPrint(
                    self.allocator,
                    "{{\"id\":\"{s}\",\"host\":\"{s}\",\"port\":{d}}}",
                    .{ n.id, n.host, n.port },
                ) catch return;
            defer self.allocator.free(entry);
            buf.appendSlice(self.allocator, entry) catch return;
        }
        buf.appendSlice(self.allocator, "]") catch return;

        const tmp_name = overlay_filename ++ ".tmp";
        {
            var f = self.data_dir.createFile(tmp_name, .{ .truncate = true }) catch return;
            defer f.close();
            f.writeAll(buf.items) catch return;
        }
        self.data_dir.rename(tmp_name, overlay_filename) catch |e| {
            std.log.warn("membership: overlay persist rename failed: {any}", .{e});
        };
    }
};

/// Parse the `"state"` string field used by `snapshotJson`/the overlay
/// file/`mergeGossip`'s wire format back into a `NodeState`.
fn parseStateStr(s: []const u8) ?NodeState {
    if (std.mem.eql(u8, s, "alive")) return .alive;
    if (std.mem.eql(u8, s, "suspect")) return .suspect;
    if (std.mem.eql(u8, s, "down")) return .down;
    if (std.mem.eql(u8, s, "draining")) return .draining;
    if (std.mem.eql(u8, s, "removed")) return .removed;
    return null;
}

// ── Tests ───────────────────────────────────────────────────────────────────

fn testConfig(peers: []const config_mod.Peer, self_idx: usize) ClusterConfig {
    return .{
        .arena = undefined,
        .enabled = true,
        .node_id = peers[self_idx].id,
        .peers = peers,
        .self_index = self_idx,
        .ec_k = 2,
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

test "membership state machine: failure threshold and generation bumps" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
        .{ .id = "n2", .host = "h2", .port = 9002 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    try std.testing.expectEqual(NodeState.alive, m.stateOf(1));
    const gen0 = m.generation.load(.monotonic);

    m.recordProbeFailure(1); // 1 -> suspect
    try std.testing.expectEqual(NodeState.suspect, m.stateOf(1));
    try std.testing.expectEqual(gen0 + 1, m.generation.load(.monotonic));

    m.recordProbeFailure(1); // 2
    try std.testing.expectEqual(NodeState.suspect, m.stateOf(1));
    m.recordProbeFailure(1); // 3 -> down
    try std.testing.expectEqual(NodeState.down, m.stateOf(1));
    try std.testing.expectEqual(gen0 + 2, m.generation.load(.monotonic));

    // Repeated failures while already down: no further generation bump.
    const gen_down = m.generation.load(.monotonic);
    m.recordProbeFailure(1);
    try std.testing.expectEqual(gen_down, m.generation.load(.monotonic));

    m.recordProbeSuccess(1); // -> alive
    try std.testing.expectEqual(NodeState.alive, m.stateOf(1));
    try std.testing.expectEqual(gen_down + 1, m.generation.load(.monotonic));

    // Repeated success while already alive: no further generation bump.
    const gen_alive = m.generation.load(.monotonic);
    m.recordProbeSuccess(1);
    try std.testing.expectEqual(gen_alive, m.generation.load(.monotonic));
}

test "addNode dedupes and persists overlay across re-init" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testConfig(&peers, 0);

    {
        const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
        defer m.deinit();
        try std.testing.expectEqual(@as(usize, 2), m.count());

        const added1 = try m.addNode("n2", "h2", 9002);
        try std.testing.expect(added1);
        try std.testing.expectEqual(@as(usize, 3), m.count());

        const added2 = try m.addNode("n2", "h2-dup", 9999);
        try std.testing.expect(!added2);
        try std.testing.expectEqual(@as(usize, 3), m.count());
    }

    // Fresh Membership over the same data_dir re-loads the overlay.
    {
        const m2 = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
        defer m2.deinit();
        try std.testing.expectEqual(@as(usize, 3), m2.count());
        try std.testing.expectEqual(NodeState.alive, m2.stateOf(2));
    }
}

test "mergeGossip adds unknown nodes and skips known ones" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    const view =
        \\[{"id":"n1","host":"h1","port":9001,"state":"alive","incarnation":0},
        \\ {"id":"n2","host":"h2","port":9002,"state":"alive","incarnation":0}]
    ;
    try m.mergeGossip(view);
    try std.testing.expectEqual(@as(usize, 3), m.count());

    // Re-merging the same view is a no-op (no duplicate n2).
    try m.mergeGossip(view);
    try std.testing.expectEqual(@as(usize, 3), m.count());
}

test "isUsable reflects down state; hostPortOf resolves joined node" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    _ = try m.addNode("n2", "joined-host", 7777);
    const hp = m.hostPortOf(2).?;
    try std.testing.expectEqualStrings("joined-host", hp.host);
    try std.testing.expectEqual(@as(u16, 7777), hp.port);

    try std.testing.expect(m.isUsable(1));
    m.recordProbeFailure(1);
    m.recordProbeFailure(1);
    m.recordProbeFailure(1);
    try std.testing.expect(!m.isUsable(1));
}

test "markDraining: usable for reads, excluded from placementIds, sticky against probe success" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
        .{ .id = "n2", .host = "h2", .port = 9002 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    try std.testing.expectError(error.UnknownNode, m.markDraining("nope"));

    try m.markDraining("n1");
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));
    try std.testing.expect(m.isUsable(1)); // still a read source

    var id_buf: [8][]const u8 = undefined;
    var idx_buf: [8]usize = undefined;
    const ids = m.placementIds(&id_buf, &idx_buf);
    try std.testing.expectEqual(@as(usize, 2), ids.len);
    for (ids) |id| try std.testing.expect(!std.mem.eql(u8, id, "n1"));

    // An ordinary probe success must not flip draining back to alive.
    m.recordProbeSuccess(1);
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));

    // Nor does a probe failure escalate it to down.
    m.recordProbeFailure(1);
    m.recordProbeFailure(1);
    m.recordProbeFailure(1);
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));

    // Idempotent re-mark.
    try m.markDraining("n1");
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));
}

test "mergeGossip adopts draining/removed opinions but never alive/suspect/down" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
        .{ .id = "n1", .host = "h1", .port = 9001 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    // A peer reporting n1 as suspect must NOT change our local view.
    try m.mergeGossip(
        \\[{"id":"n1","host":"h1","port":9001,"state":"suspect"}]
    );
    try std.testing.expectEqual(NodeState.alive, m.stateOf(1));

    // A peer reporting n1 as draining IS adopted.
    try m.mergeGossip(
        \\[{"id":"n1","host":"h1","port":9001,"state":"draining"}]
    );
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));

    // A later "alive" opinion must not undo the draining state.
    try m.mergeGossip(
        \\[{"id":"n1","host":"h1","port":9001,"state":"alive"}]
    );
    try std.testing.expectEqual(NodeState.draining, m.stateOf(1));

    // removed beats draining and is terminal.
    try m.mergeGossip(
        \\[{"id":"n1","host":"h1","port":9001,"state":"removed"}]
    );
    try std.testing.expectEqual(NodeState.removed, m.stateOf(1));
    try m.mergeGossip(
        \\[{"id":"n1","host":"h1","port":9001,"state":"draining"}]
    );
    try std.testing.expectEqual(NodeState.removed, m.stateOf(1));
}

test "markRemoved drops the node from the persisted overlay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const peers = [_]config_mod.Peer{
        .{ .id = "n0", .host = "h0", .port = 9000 },
    };
    const cfg = testConfig(&peers, 0);
    const m = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m.deinit();

    _ = try m.addNode("n1", "h1", 9001);
    _ = try m.addNode("n2", "h2", 9002);
    try m.markDraining("n1");

    try std.testing.expectError(error.UnknownNode, m.markRemoved("nope"));
    try m.markRemoved("n1");
    try std.testing.expectEqual(NodeState.removed, m.stateOf(1));
    try std.testing.expect(!m.isUsable(1));

    // Idempotent.
    try m.markRemoved("n1");
    try std.testing.expectEqual(NodeState.removed, m.stateOf(1));

    // Re-loading from the persisted overlay must NOT resurrect n1 (dropped
    // entirely) — a fresh Membership over the same data_dir only re-learns
    // n2 (never removed).
    const m2 = try Membership.init(std.testing.allocator, &cfg, tmp.dir);
    defer m2.deinit();
    try std.testing.expectEqual(@as(usize, 2), m2.count()); // n0 (config) + n2 (overlay)
    try std.testing.expectEqualStrings("n2", m2.nodes.items[1].id);
}
