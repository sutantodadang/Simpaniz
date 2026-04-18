//! Rendezvous (Highest Random Weight, HRW) hashing for object placement.
//!
//! Given a key and a set of nodes, deterministically pick the top-N nodes
//! that should host the key. Adding or removing one node only reshuffles
//! O(1/N) of the keys.
//!
//! Score function: SHA-256(node_id || 0x00 || key)[0..8] as u64 BE.

const std = @import("std");

pub const max_picks: usize = 32;

/// One placement decision: nodes ordered by descending score, highest first.
pub const Placement = struct {
    indices: [max_picks]usize,
    len: usize,

    pub fn slice(self: *const Placement) []const usize {
        return self.indices[0..self.len];
    }
};

/// Pick the top `n` node indices from `nodes` for `key`.
/// `nodes[i]` is the node identifier (e.g. "node-1"). Returns indices in
/// descending score order, so `result[0]` is the primary owner.
pub fn pick(nodes: []const []const u8, key: []const u8, n: usize) !Placement {
    if (n == 0 or n > max_picks) return error.InvalidArgument;
    if (nodes.len < n) return error.NotEnoughNodes;

    var scores: [max_picks * 4]u64 = undefined;
    var idxs: [max_picks * 4]usize = undefined;
    if (nodes.len > scores.len) return error.TooManyNodes;

    for (nodes, 0..) |node, i| {
        scores[i] = scoreFor(node, key);
        idxs[i] = i;
    }

    // Partial selection-sort for top n (n is tiny — k+m ≤ 32).
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < nodes.len) : (j += 1) {
            if (scores[j] > scores[best]) best = j;
        }
        if (best != i) {
            const ts = scores[i];
            scores[i] = scores[best];
            scores[best] = ts;
            const ti = idxs[i];
            idxs[i] = idxs[best];
            idxs[best] = ti;
        }
    }

    var p: Placement = .{ .indices = undefined, .len = n };
    for (0..n) |k| p.indices[k] = idxs[k];
    return p;
}

fn scoreFor(node: []const u8, key: []const u8) u64 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(node);
    h.update(&[_]u8{0});
    h.update(key);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.mem.readInt(u64, digest[0..8], .big);
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "pick returns deterministic result" {
    const nodes = [_][]const u8{ "a", "b", "c", "d", "e" };
    const p1 = try pick(&nodes, "bucket/key", 3);
    const p2 = try pick(&nodes, "bucket/key", 3);
    try std.testing.expectEqualSlices(usize, p1.slice(), p2.slice());
    try std.testing.expectEqual(@as(usize, 3), p1.len);
}

test "removing a non-owner does not perturb placement" {
    const nodes_a = [_][]const u8{ "a", "b", "c", "d", "e" };
    const p_a = try pick(&nodes_a, "k1", 2);
    const owner_a = nodes_a[p_a.indices[0]];

    // Drop a known non-owner.
    var to_drop: []const u8 = "";
    for (nodes_a) |n| {
        if (!std.mem.eql(u8, n, owner_a)) {
            to_drop = n;
            break;
        }
    }
    var kept: [4][]const u8 = undefined;
    var ki: usize = 0;
    for (nodes_a) |n| {
        if (std.mem.eql(u8, n, to_drop)) continue;
        kept[ki] = n;
        ki += 1;
    }
    const p_b = try pick(kept[0..ki], "k1", 2);
    const owner_b = kept[p_b.indices[0]];
    try std.testing.expect(std.mem.eql(u8, owner_a, owner_b));
}

test "pick distributes keys across nodes" {
    const nodes = [_][]const u8{ "n1", "n2", "n3", "n4" };
    var counts = [_]usize{0} ** 4;
    var key_buf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const key = try std.fmt.bufPrint(&key_buf, "k-{d}", .{i});
        const p = try pick(&nodes, key, 1);
        counts[p.indices[0]] += 1;
    }
    // Each node should hold roughly 250 ± 80 keys.
    for (counts) |c| try std.testing.expect(c > 150 and c < 350);
}

test "pick errors on invalid args" {
    const nodes = [_][]const u8{"a"};
    try std.testing.expectError(error.NotEnoughNodes, pick(&nodes, "k", 2));
    try std.testing.expectError(error.InvalidArgument, pick(&nodes, "k", 0));
}
