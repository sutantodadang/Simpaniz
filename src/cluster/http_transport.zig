//! HTTP/1.1 shard transport. Each call opens a fresh TCP connection,
//! issues a single Connection: close request, and reads back the
//! response. Authenticated via a shared cluster secret in the
//! `X-Simpaniz-Cluster-Auth` header.
//!
//! For the local node (node == self_index) we short-circuit straight
//! to the on-disk `disk_store` to avoid a network hop.
//!
//! Inter-node socket I/O uses `cfg.connect_timeout_ms` as both
//! send and receive timeout.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;
const ShardId = transport_mod.ShardId;
const config_mod = @import("config.zig");
const ClusterConfig = config_mod.ClusterConfig;
const Peer = config_mod.Peer;
const disk = @import("disk_store.zig");
const membership_mod = @import("membership.zig");
const Membership = membership_mod.Membership;

pub const HttpTransport = struct {
    allocator: Allocator,
    cfg: *const ClusterConfig,
    data_dir: std.fs.Dir,
    metrics: ?*Metrics = null,
    /// Set after construction (see `ClusterRuntime.init`). Consulted by
    /// `peerOf` to resolve host:port for node indices beyond the static
    /// `cfg.peers` list — i.e. nodes that joined dynamically at runtime.
    membership: ?*Membership = null,

    pub const Metrics = struct {
        peer_unreachable: std.atomic.Value(u64) = .{ .raw = 0 },
        shard_put_ok: std.atomic.Value(u64) = .{ .raw = 0 },
        shard_put_err: std.atomic.Value(u64) = .{ .raw = 0 },
        shard_get_ok: std.atomic.Value(u64) = .{ .raw = 0 },
        shard_get_err: std.atomic.Value(u64) = .{ .raw = 0 },
        meta_put_ok: std.atomic.Value(u64) = .{ .raw = 0 },
        meta_put_err: std.atomic.Value(u64) = .{ .raw = 0 },
        meta_get_ok: std.atomic.Value(u64) = .{ .raw = 0 },
        meta_get_err: std.atomic.Value(u64) = .{ .raw = 0 },
        bucket_op_ok: std.atomic.Value(u64) = .{ .raw = 0 },
        bucket_op_err: std.atomic.Value(u64) = .{ .raw = 0 },
    };

    pub fn init(allocator: Allocator, cfg: *const ClusterConfig, data_dir: std.fs.Dir) HttpTransport {
        return .{ .allocator = allocator, .cfg = cfg, .data_dir = data_dir };
    }

    pub fn transport(self: *HttpTransport) Transport {
        return .{ .ctx = self, .vtable = &.{
            .putShard = putShardVT,
            .getShard = getShardVT,
            .deleteShard = deleteShardVT,
            .putMeta = putMetaVT,
            .getMeta = getMetaVT,
            .deleteMeta = deleteMetaVT,
            .appendShardChunk = appendShardChunkVT,
            .getShardRange = getShardRangeVT,
            .statShard = statShardVT,
        } };
    }

    fn isSelf(self: *HttpTransport, node: usize) bool {
        return node == self.cfg.self_index;
    }

    fn peerOf(self: *HttpTransport, node: usize) !Peer {
        if (node < self.cfg.peers.len) return self.cfg.peers[node];
        if (self.membership) |mem| {
            if (mem.hostPortOf(node)) |hp| return .{ .id = "", .host = hp.host, .port = hp.port };
        }
        return error.InvalidNode;
    }

    /// Probe `node` and return its membership snapshot JSON body (caller
    /// frees with `allocator`). Used by the `Membership` prober thread.
    pub fn ping(self: *HttpTransport, node: usize, allocator: Allocator) ![]u8 {
        const peer = try self.peerOf(node);
        const r = try self.doRequest(peer, "GET", "/_simpaniz/ping", "", true);
        switch (r) {
            .not_found => return error.PeerError,
            .ok => |bytes| {
                const out = try allocator.alloc(u8, bytes.len);
                @memcpy(out, bytes);
                self.allocator.free(bytes);
                return out;
            },
        }
    }

    fn pingPingerFn(ctx: *anyopaque, node_idx: usize, allocator: Allocator) anyerror![]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        return self.ping(node_idx, allocator);
    }

    /// Adapter handing this transport's `ping` to `Membership.start` without
    /// `membership.zig` needing to depend on `HttpTransport`.
    pub fn pinger(self: *HttpTransport) membership_mod.Pinger {
        return .{ .ctx = self, .pingFn = pingPingerFn };
    }

    /// Announce this node to `node` via the internal join endpoint. Returns
    /// the peer's membership snapshot JSON body (caller frees).
    pub fn join(self: *HttpTransport, node: usize, self_id: []const u8, self_host: []const u8, self_port: u16, allocator: Allocator) ![]u8 {
        const peer = try self.peerOf(node);
        var body_buf: [512]u8 = undefined;
        const body = try std.fmt.bufPrint(
            &body_buf,
            "{{\"id\":\"{s}\",\"host\":\"{s}\",\"port\":{d}}}",
            .{ self_id, self_host, self_port },
        );
        const r = try self.doRequest(peer, "POST", "/_simpaniz/join", body, true);
        switch (r) {
            .not_found => return error.PeerError,
            .ok => |bytes| {
                const out = try allocator.alloc(u8, bytes.len);
                @memcpy(out, bytes);
                self.allocator.free(bytes);
                return out;
            },
        }
    }

    /// Replicate a bucket op (PUT / DELETE) to a single peer. Idempotent
    /// at the storage layer. Self-node short-circuits to local storage.
    /// `local_op` is invoked when the target is `self_index`.
    pub fn bucketOp(
        self: *HttpTransport,
        node: usize,
        method: []const u8,
        bucket: []const u8,
    ) !void {
        if (self.isSelf(node)) return; // caller handled local already
        var pb: [256]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/bucket/{s}", .{bucket});
        const peer = try self.peerOf(node);
        _ = self.doRequest(peer, method, path, "", false) catch |e| {
            if (self.metrics) |m| _ = m.bucket_op_err.fetchAdd(1, .monotonic);
            return e;
        };
        if (self.metrics) |m| _ = m.bucket_op_ok.fetchAdd(1, .monotonic);
    }

    // ── vtable thunks ─────────────────────────────────────────────────────

    fn putShardVT(ctx: *anyopaque, node: usize, sid: ShardId, data: []const u8) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.putShard(self.data_dir, sid.bucket, sid.key, sid.index, data);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}", .{ sid.bucket, sid.key, sid.index });
        const peer = try self.peerOf(node);
        _ = self.doRequest(peer, "PUT", path, data, false) catch |e| {
            if (self.metrics) |m| _ = m.shard_put_err.fetchAdd(1, .monotonic);
            return e;
        };
        if (self.metrics) |m| _ = m.shard_put_ok.fetchAdd(1, .monotonic);
    }

    fn getShardVT(ctx: *anyopaque, node: usize, sid: ShardId, allocator: Allocator) anyerror!?[]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.getShard(self.data_dir, sid.bucket, sid.key, sid.index, allocator);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}", .{ sid.bucket, sid.key, sid.index });
        const peer = try self.peerOf(node);
        const r = self.doRequest(peer, "GET", path, "", true) catch |e| {
            if (self.metrics) |m| _ = m.shard_get_err.fetchAdd(1, .monotonic);
            return e;
        };
        switch (r) {
            .not_found => return null,
            .ok => |bytes| {
                if (self.metrics) |m| _ = m.shard_get_ok.fetchAdd(1, .monotonic);
                const out = try allocator.alloc(u8, bytes.len);
                @memcpy(out, bytes);
                self.allocator.free(bytes);
                return out;
            },
        }
    }

    fn deleteShardVT(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.deleteShard(self.data_dir, sid.bucket, sid.key, sid.index);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}", .{ sid.bucket, sid.key, sid.index });
        const peer = try self.peerOf(node);
        _ = try self.doRequest(peer, "DELETE", path, "", false);
    }

    // ponytail: chunk-append/range-read/stat each open a fresh short-lived
    // TCP connection per call (same as putShard/getShard above) — no
    // keep-alive pooling in v1. Acceptable: stripe chunks are ~1 MiB so the
    // connection-setup overhead is amortized; revisit if profiling shows
    // connect() dominating cluster PUT/GET latency.
    fn appendShardChunkVT(ctx: *anyopaque, node: usize, sid: ShardId, seq: u64, data: []const u8) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.appendShardChunk(self.data_dir, sid.bucket, sid.key, sid.index, seq, data);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}?seq={d}", .{ sid.bucket, sid.key, sid.index, seq });
        const peer = try self.peerOf(node);
        _ = self.doRequest(peer, "PUT", path, data, false) catch |e| {
            if (self.metrics) |m| _ = m.shard_put_err.fetchAdd(1, .monotonic);
            return e;
        };
        if (self.metrics) |m| _ = m.shard_put_ok.fetchAdd(1, .monotonic);
    }

    fn getShardRangeVT(ctx: *anyopaque, node: usize, sid: ShardId, offset: u64, buf: []u8) anyerror!usize {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.getShardRange(self.data_dir, sid.bucket, sid.key, sid.index, offset, buf);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}?offset={d}&len={d}", .{ sid.bucket, sid.key, sid.index, offset, buf.len });
        const peer = try self.peerOf(node);
        const r = self.doRequest(peer, "GET", path, "", true) catch |e| {
            if (self.metrics) |m| _ = m.shard_get_err.fetchAdd(1, .monotonic);
            return e;
        };
        switch (r) {
            .not_found => return error.ShardMissing,
            .ok => |bytes| {
                defer self.allocator.free(bytes);
                if (self.metrics) |m| _ = m.shard_get_ok.fetchAdd(1, .monotonic);
                if (bytes.len > buf.len) return error.RangeTooLarge;
                @memcpy(buf[0..bytes.len], bytes);
                return bytes.len;
            },
        }
    }

    fn statShardVT(ctx: *anyopaque, node: usize, sid: ShardId) anyerror!u64 {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.statShard(self.data_dir, sid.bucket, sid.key, sid.index);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/shards/{s}/{s}/{d}?stat=1", .{ sid.bucket, sid.key, sid.index });
        const peer = try self.peerOf(node);
        const r = self.doRequest(peer, "GET", path, "", true) catch |e| {
            if (self.metrics) |m| _ = m.shard_get_err.fetchAdd(1, .monotonic);
            return e;
        };
        switch (r) {
            .not_found => return error.ShardMissing,
            .ok => |bytes| {
                defer self.allocator.free(bytes);
                if (self.metrics) |m| _ = m.shard_get_ok.fetchAdd(1, .monotonic);
                return std.fmt.parseInt(u64, bytes, 10) catch error.MalformedResponse;
            },
        }
    }

    fn putMetaVT(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, data: []const u8) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.putMeta(self.data_dir, bucket, key, data);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/meta/{s}/{s}", .{ bucket, key });
        const peer = try self.peerOf(node);
        _ = self.doRequest(peer, "PUT", path, data, false) catch |e| {
            if (self.metrics) |m| _ = m.meta_put_err.fetchAdd(1, .monotonic);
            return e;
        };
        if (self.metrics) |m| _ = m.meta_put_ok.fetchAdd(1, .monotonic);
    }

    fn getMetaVT(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8, allocator: Allocator) anyerror!?[]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.getMeta(self.data_dir, bucket, key, allocator);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/meta/{s}/{s}", .{ bucket, key });
        const peer = try self.peerOf(node);
        const r = self.doRequest(peer, "GET", path, "", true) catch |e| {
            if (self.metrics) |m| _ = m.meta_get_err.fetchAdd(1, .monotonic);
            return e;
        };
        switch (r) {
            .not_found => return null,
            .ok => |bytes| {
                if (self.metrics) |m| _ = m.meta_get_ok.fetchAdd(1, .monotonic);
                const out = try allocator.alloc(u8, bytes.len);
                @memcpy(out, bytes);
                self.allocator.free(bytes);
                return out;
            },
        }
    }

    fn deleteMetaVT(ctx: *anyopaque, node: usize, bucket: []const u8, key: []const u8) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ctx));
        if (self.isSelf(node)) return disk.deleteMeta(self.data_dir, bucket, key);
        var pb: [512]u8 = undefined;
        const path = try std.fmt.bufPrint(&pb, "/_simpaniz/meta/{s}/{s}", .{ bucket, key });
        const peer = try self.peerOf(node);
        _ = try self.doRequest(peer, "DELETE", path, "", false);
    }

    // ── HTTP/1.1 client ───────────────────────────────────────────────────

    const Result = union(enum) {
        ok: []u8, // body, owned by self.allocator
        not_found,
    };

    fn applyTimeouts(handle: std.posix.socket_t, ms: u32) void {
        if (ms == 0) return;
        if (builtin.os.tag == .windows) {
            const ms_dword: u32 = ms;
            const bytes = std.mem.asBytes(&ms_dword);
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
        } else {
            const tv = std.posix.timeval{
                .sec = @intCast(ms / 1000),
                .usec = @intCast((ms % 1000) * 1000),
            };
            const bytes = std.mem.asBytes(&tv);
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
        }
    }

    fn doRequest(self: *HttpTransport, peer: Peer, method: []const u8, path: []const u8, body: []const u8, want_body: bool) !Result {
        var stream = std.net.tcpConnectToHost(self.allocator, peer.host, peer.port) catch |e| {
            if (self.metrics) |m| _ = m.peer_unreachable.fetchAdd(1, .monotonic);
            return e;
        };
        defer stream.close();
        applyTimeouts(stream.handle, self.cfg.connect_timeout_ms);

        // Build request head.
        var head_buf: [1024]u8 = undefined;
        const head = try std.fmt.bufPrint(&head_buf,
            "{s} {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Length: {d}\r\nX-Simpaniz-Cluster-Auth: {s}\r\n\r\n",
            .{ method, path, peer.host, peer.port, body.len, self.cfg.cluster_secret },
        );

        var write_buf: [8 * 1024]u8 = undefined;
        var sw = stream.writer(&write_buf);
        try sw.interface.writeAll(head);
        if (body.len > 0) try sw.interface.writeAll(body);
        try sw.interface.flush();

        // Parse response.
        var read_buf: [16 * 1024]u8 = undefined;
        var sr = stream.reader(&read_buf);
        const reader = sr.interface();

        const status_line = reader.takeDelimiterInclusive('\n') catch return error.ReadFailed;
        const trimmed = std.mem.trimRight(u8, status_line, "\r\n");
        const sp1 = std.mem.indexOfScalar(u8, trimmed, ' ') orelse return error.MalformedResponse;
        const after = trimmed[sp1 + 1 ..];
        const sp2 = std.mem.indexOfScalar(u8, after, ' ') orelse after.len;
        const code_str = after[0..sp2];
        const status = std.fmt.parseInt(u16, code_str, 10) catch return error.MalformedResponse;

        var content_length: ?u64 = null;
        while (true) {
            const line = reader.takeDelimiterInclusive('\n') catch return error.ReadFailed;
            const ln = std.mem.trimRight(u8, line, "\r\n");
            if (ln.len == 0) break;
            if (std.mem.indexOfScalar(u8, ln, ':')) |colon| {
                const name = ln[0..colon];
                const value = std.mem.trimLeft(u8, ln[colon + 1 ..], " \t");
                if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                    content_length = std.fmt.parseInt(u64, value, 10) catch null;
                }
            }
        }

        if (status == 404) {
            if (content_length) |n| {
                if (n > 0) {
                    const buf = try self.allocator.alloc(u8, @intCast(n));
                    defer self.allocator.free(buf);
                    _ = try reader.readSliceShort(buf);
                }
            }
            return .not_found;
        }
        if (status >= 200 and status < 300) {
            if (!want_body) return .{ .ok = &[_]u8{} };
            const n = content_length orelse return error.MissingContentLength;
            const buf = try self.allocator.alloc(u8, @intCast(n));
            errdefer self.allocator.free(buf);
            try reader.readSliceAll(buf);
            return .{ .ok = buf };
        }
        return error.PeerError;
    }
};

