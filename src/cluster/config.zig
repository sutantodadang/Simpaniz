//! Cluster identity, peer list, and erasure-coding parameters.
//!
//! Parsed once at boot from environment variables. Owns its own arena.
//!
//! Env vars:
//!   SIMPANIZ_NODE_ID         this node's id (e.g. "node-1"). Empty → cluster mode off.
//!   SIMPANIZ_PEERS           comma list of "id@host:port" entries.
//!                             MUST include this node (matched by id).
//!   SIMPANIZ_EC_K            data shards (default 4)
//!   SIMPANIZ_EC_M            parity shards (default 2)
//!   SIMPANIZ_CLUSTER_SECRET  shared secret used in `X-Simpaniz-Cluster-Auth`
//!                             header on internal shard transfers.
//!
//! When `enabled == false`, the server runs as a standalone single node
//! (current behaviour).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Peer = struct {
    id: []const u8,
    host: []const u8,
    port: u16,
};

pub const ClusterConfig = struct {
    arena: std.heap.ArenaAllocator,

    enabled: bool,
    node_id: []const u8,
    peers: []const Peer,
    /// Index of `self` inside `peers`.
    self_index: usize,

    ec_k: u8,
    ec_m: u8,
    cluster_secret: []const u8,
    /// Per-call HTTP timeout for inter-node shard transfers, milliseconds.
    /// Applies to send + receive on the socket via SO_SNDTIMEO/SO_RCVTIMEO.
    /// Connect itself uses the OS default; tune via firewall/network if needed.
    connect_timeout_ms: u32,
    /// Replication targets for SSR. Comma-separated `bucket=>scheme://host:port[/dst-bucket]`.
    /// Example: `imgs=>http://dr.example.com:9000/imgs,videos=>http://dr.example.com:9000`.
    /// Empty disables SSR.
    repl_targets_raw: []const u8,

    pub fn deinit(self: *ClusterConfig) void {
        self.arena.deinit();
    }

    pub fn shardCount(self: *const ClusterConfig) usize {
        return @as(usize, self.ec_k) + @as(usize, self.ec_m);
    }

    /// `[]const []const u8` view of peer ids — handy for rendezvous.pick.
    pub fn peerIds(self: *const ClusterConfig, out: [][]const u8) []const []const u8 {
        const n = @min(out.len, self.peers.len);
        for (0..n) |i| out[i] = self.peers[i].id;
        return out[0..n];
    }
};

pub fn load(parent_allocator: Allocator) !ClusterConfig {
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const node_id = getEnv(a, "SIMPANIZ_NODE_ID", "");
    const peers_raw = getEnv(a, "SIMPANIZ_PEERS", "");
    const ec_k = parseU8(getEnv(a, "SIMPANIZ_EC_K", "4"), 4);
    const ec_m = parseU8(getEnv(a, "SIMPANIZ_EC_M", "2"), 2);
    const secret = getEnv(a, "SIMPANIZ_CLUSTER_SECRET", "");
    const timeout = parseU32(getEnv(a, "SIMPANIZ_CLUSTER_TIMEOUT_MS", "5000"), 5000);
    const repl = getEnv(a, "SIMPANIZ_REPL_TARGETS", "");

    if (node_id.len == 0 or peers_raw.len == 0) {
        return .{
            .arena = arena,
            .enabled = false,
            .node_id = node_id,
            .peers = &.{},
            .self_index = 0,
            .ec_k = ec_k,
            .ec_m = ec_m,
            .cluster_secret = secret,
            .connect_timeout_ms = timeout,
            .repl_targets_raw = repl,
        };
    }

    const peers = try parsePeers(a, peers_raw);
    if (peers.len == 0) return error.NoPeers;
    if (ec_k == 0 or ec_m == 0) return error.InvalidEcParams;
    if (@as(usize, ec_k) + @as(usize, ec_m) > peers.len) {
        std.log.err(
            "SIMPANIZ_EC_K + SIMPANIZ_EC_M ({d}) exceeds peer count ({d})",
            .{ @as(usize, ec_k) + @as(usize, ec_m), peers.len },
        );
        return error.NotEnoughPeers;
    }

    var self_index: ?usize = null;
    for (peers, 0..) |p, i| {
        if (std.mem.eql(u8, p.id, node_id)) {
            self_index = i;
            break;
        }
    }
    const si = self_index orelse {
        std.log.err("SIMPANIZ_NODE_ID '{s}' not found in SIMPANIZ_PEERS", .{node_id});
        return error.SelfNotInPeers;
    };

    if (secret.len < 16) {
        std.log.err("SIMPANIZ_CLUSTER_SECRET must be at least 16 chars", .{});
        return error.WeakClusterSecret;
    }

    return .{
        .arena = arena,
        .enabled = true,
        .node_id = node_id,
        .peers = peers,
        .self_index = si,
        .ec_k = ec_k,
        .ec_m = ec_m,
        .cluster_secret = secret,
        .connect_timeout_ms = timeout,
        .repl_targets_raw = repl,
    };
}

fn parseU32(s: []const u8, default: u32) u32 {
    return std.fmt.parseInt(u32, s, 10) catch default;
}

fn parsePeers(a: Allocator, raw: []const u8) ![]const Peer {
    var list: std.ArrayList(Peer) = .{};
    errdefer {
        for (list.items) |p| {
            a.free(p.id);
            a.free(p.host);
        }
        list.deinit(a);
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const at = std.mem.indexOfScalar(u8, entry, '@') orelse return error.InvalidPeerSpec;
        const id = std.mem.trim(u8, entry[0..at], " \t");
        const hp = entry[at + 1 ..];
        const colon = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return error.InvalidPeerSpec;
        const host = std.mem.trim(u8, hp[0..colon], " \t");
        const port_s = std.mem.trim(u8, hp[colon + 1 ..], " \t");
        if (id.len == 0 or host.len == 0 or port_s.len == 0) return error.InvalidPeerSpec;
        const port = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidPeerSpec;
        const id_owned = try a.dupe(u8, id);
        errdefer a.free(id_owned);
        const host_owned = try a.dupe(u8, host);
        errdefer a.free(host_owned);
        try list.append(a, .{ .id = id_owned, .host = host_owned, .port = port });
    }

    // Reject duplicate ids.
    for (list.items, 0..) |p, i| for (list.items[i + 1 ..]) |q| {
        if (std.mem.eql(u8, p.id, q.id)) return error.DuplicatePeerId;
    };

    return try list.toOwnedSlice(a);
}

fn getEnv(a: Allocator, key: []const u8, default: []const u8) []const u8 {
    return std.process.getEnvVarOwned(a, key) catch a.dupe(u8, default) catch default;
}

fn parseU8(s: []const u8, default: u8) u8 {
    return std.fmt.parseInt(u8, s, 10) catch default;
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "parsePeers basic" {
    const a = std.testing.allocator;
    const peers = try parsePeers(a, "n1@127.0.0.1:9000, n2@10.0.0.2:9001 ,n3@host:9002");
    defer {
        for (peers) |p| {
            a.free(p.id);
            a.free(p.host);
        }
        a.free(peers);
    }
    try std.testing.expectEqual(@as(usize, 3), peers.len);
    try std.testing.expectEqualStrings("n1", peers[0].id);
    try std.testing.expectEqualStrings("127.0.0.1", peers[0].host);
    try std.testing.expectEqual(@as(u16, 9000), peers[0].port);
    try std.testing.expectEqualStrings("n3", peers[2].id);
    try std.testing.expectEqual(@as(u16, 9002), peers[2].port);
}

test "parsePeers rejects bad spec" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidPeerSpec, parsePeers(a, "noatsign:9000"));
    try std.testing.expectError(error.InvalidPeerSpec, parsePeers(a, "n1@host"));
    try std.testing.expectError(error.InvalidPeerSpec, parsePeers(a, "n1@host:notanumber"));
}

test "parsePeers rejects duplicate ids" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.DuplicatePeerId, parsePeers(a, "n1@h1:9000,n1@h2:9001"));
}
