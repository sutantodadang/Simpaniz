//! Lightweight Prometheus text-format metrics for Simpaniz.
//! All counters are atomic; histogram buckets use lock-free additions.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Counter = struct {
    value: std.atomic.Value(u64) = .init(0),

    pub fn inc(self: *Counter) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }
    pub fn add(self: *Counter, n: u64) void {
        _ = self.value.fetchAdd(n, .monotonic);
    }
    pub fn set(self: *Counter, n: u64) void {
        self.value.store(n, .monotonic);
    }
    pub fn get(self: *Counter) u64 {
        return self.value.load(.monotonic);
    }
};

const latency_buckets_ms = [_]f64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10_000 };

pub const Histogram = struct {
    buckets: [latency_buckets_ms.len + 1]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    sum_ms: std.atomic.Value(u64) = .init(0),

    pub fn observeMs(self: *Histogram, ms: u64) void {
        const ms_f: f64 = @floatFromInt(ms);
        var i: usize = 0;
        while (i < latency_buckets_ms.len) : (i += 1) {
            if (ms_f <= latency_buckets_ms[i]) {
                _ = self.buckets[i].fetchAdd(1, .monotonic);
                break;
            }
        }
        if (i == latency_buckets_ms.len) _ = self.buckets[i].fetchAdd(1, .monotonic);
        _ = self.sum_ms.fetchAdd(ms, .monotonic);
    }
};

pub const Registry = struct {
    requests_total: Counter = .{},
    requests_in_flight: std.atomic.Value(i64) = .init(0),
    bytes_in: Counter = .{},
    bytes_out: Counter = .{},
    auth_failures: Counter = .{},
    errors_total: Counter = .{},
    bitrot_ok_total: Counter = .{},
    bitrot_errors_total: Counter = .{},
    lifecycle_expirations_total: Counter = .{},
    heal_repaired_total: Counter = .{},
    /// Cluster transport counters (optional — only set when running cluster mode).
    cluster_peer_unreachable: Counter = .{},
    cluster_shard_put_ok: Counter = .{},
    cluster_shard_put_err: Counter = .{},
    cluster_shard_get_ok: Counter = .{},
    cluster_shard_get_err: Counter = .{},
    cluster_meta_put_ok: Counter = .{},
    cluster_meta_put_err: Counter = .{},
    cluster_meta_get_ok: Counter = .{},
    cluster_meta_get_err: Counter = .{},
    cluster_bucket_op_ok: Counter = .{},
    cluster_bucket_op_err: Counter = .{},
    /// Cross-cluster replication counters (set by SSR daemon).
    repl_queued_total: Counter = .{},
    repl_replicated_total: Counter = .{},
    repl_failed_total: Counter = .{},
    repl_pending: Counter = .{}, // gauge-style: set, not added
    request_latency_ms: Histogram = .{},
    started_unix: i64 = 0,

    pub fn render(self: *Registry, allocator: Allocator) ![]u8 {
        var out = std.ArrayList(u8){};
        errdefer out.deinit(allocator);
        var w = out.writer(allocator);

        try w.print("# HELP simpaniz_requests_total Total HTTP requests.\n", .{});
        try w.print("# TYPE simpaniz_requests_total counter\n", .{});
        try w.print("simpaniz_requests_total {d}\n", .{self.requests_total.get()});

        try w.print("# HELP simpaniz_requests_in_flight In-flight HTTP requests.\n", .{});
        try w.print("# TYPE simpaniz_requests_in_flight gauge\n", .{});
        try w.print("simpaniz_requests_in_flight {d}\n", .{self.requests_in_flight.load(.monotonic)});

        try w.print("# HELP simpaniz_bytes_in_total Bytes received from clients.\n", .{});
        try w.print("# TYPE simpaniz_bytes_in_total counter\n", .{});
        try w.print("simpaniz_bytes_in_total {d}\n", .{self.bytes_in.get()});

        try w.print("# HELP simpaniz_bytes_out_total Bytes written to clients.\n", .{});
        try w.print("# TYPE simpaniz_bytes_out_total counter\n", .{});
        try w.print("simpaniz_bytes_out_total {d}\n", .{self.bytes_out.get()});

        try w.print("# HELP simpaniz_auth_failures_total Auth failures.\n", .{});
        try w.print("# TYPE simpaniz_auth_failures_total counter\n", .{});
        try w.print("simpaniz_auth_failures_total {d}\n", .{self.auth_failures.get()});

        try w.print("# HELP simpaniz_errors_total Responses with status >= 500.\n", .{});
        try w.print("# TYPE simpaniz_errors_total counter\n", .{});
        try w.print("simpaniz_errors_total {d}\n", .{self.errors_total.get()});

        try w.print("# HELP simpaniz_bitrot_ok_total Successful bitrot verifications.\n", .{});
        try w.print("# TYPE simpaniz_bitrot_ok_total counter\n", .{});
        try w.print("simpaniz_bitrot_ok_total {d}\n", .{self.bitrot_ok_total.get()});

        try w.print("# HELP simpaniz_bitrot_errors_total Bitrot verification failures.\n", .{});
        try w.print("# TYPE simpaniz_bitrot_errors_total counter\n", .{});
        try w.print("simpaniz_bitrot_errors_total {d}\n", .{self.bitrot_errors_total.get()});

        try w.print("# HELP simpaniz_lifecycle_expirations_total Objects expired by lifecycle rules.\n", .{});
        try w.print("# TYPE simpaniz_lifecycle_expirations_total counter\n", .{});
        try w.print("simpaniz_lifecycle_expirations_total {d}\n", .{self.lifecycle_expirations_total.get()});

        try w.print("# HELP simpaniz_heal_repaired_total Shards repaired by the cluster heal daemon.\n", .{});
        try w.print("# TYPE simpaniz_heal_repaired_total counter\n", .{});
        try w.print("simpaniz_heal_repaired_total {d}\n", .{self.heal_repaired_total.get()});

        try w.print("# HELP simpaniz_cluster_peer_unreachable_total Failed inter-node TCP connects.\n", .{});
        try w.print("# TYPE simpaniz_cluster_peer_unreachable_total counter\n", .{});
        try w.print("simpaniz_cluster_peer_unreachable_total {d}\n", .{self.cluster_peer_unreachable.get()});

        try w.print("# TYPE simpaniz_cluster_shard_put_ok_total counter\n", .{});
        try w.print("simpaniz_cluster_shard_put_ok_total {d}\n", .{self.cluster_shard_put_ok.get()});
        try w.print("# TYPE simpaniz_cluster_shard_put_err_total counter\n", .{});
        try w.print("simpaniz_cluster_shard_put_err_total {d}\n", .{self.cluster_shard_put_err.get()});
        try w.print("# TYPE simpaniz_cluster_shard_get_ok_total counter\n", .{});
        try w.print("simpaniz_cluster_shard_get_ok_total {d}\n", .{self.cluster_shard_get_ok.get()});
        try w.print("# TYPE simpaniz_cluster_shard_get_err_total counter\n", .{});
        try w.print("simpaniz_cluster_shard_get_err_total {d}\n", .{self.cluster_shard_get_err.get()});
        try w.print("# TYPE simpaniz_cluster_meta_put_ok_total counter\n", .{});
        try w.print("simpaniz_cluster_meta_put_ok_total {d}\n", .{self.cluster_meta_put_ok.get()});
        try w.print("# TYPE simpaniz_cluster_meta_put_err_total counter\n", .{});
        try w.print("simpaniz_cluster_meta_put_err_total {d}\n", .{self.cluster_meta_put_err.get()});
        try w.print("# TYPE simpaniz_cluster_meta_get_ok_total counter\n", .{});
        try w.print("simpaniz_cluster_meta_get_ok_total {d}\n", .{self.cluster_meta_get_ok.get()});
        try w.print("# TYPE simpaniz_cluster_meta_get_err_total counter\n", .{});
        try w.print("simpaniz_cluster_meta_get_err_total {d}\n", .{self.cluster_meta_get_err.get()});
        try w.print("# TYPE simpaniz_cluster_bucket_op_ok_total counter\n", .{});
        try w.print("simpaniz_cluster_bucket_op_ok_total {d}\n", .{self.cluster_bucket_op_ok.get()});
        try w.print("# TYPE simpaniz_cluster_bucket_op_err_total counter\n", .{});
        try w.print("simpaniz_cluster_bucket_op_err_total {d}\n", .{self.cluster_bucket_op_err.get()});

        try w.print("# HELP simpaniz_repl_queued_total Cross-cluster replication tasks enqueued.\n", .{});
        try w.print("# TYPE simpaniz_repl_queued_total counter\n", .{});
        try w.print("simpaniz_repl_queued_total {d}\n", .{self.repl_queued_total.get()});
        try w.print("# TYPE simpaniz_repl_replicated_total counter\n", .{});
        try w.print("simpaniz_repl_replicated_total {d}\n", .{self.repl_replicated_total.get()});
        try w.print("# TYPE simpaniz_repl_failed_total counter\n", .{});
        try w.print("simpaniz_repl_failed_total {d}\n", .{self.repl_failed_total.get()});
        try w.print("# HELP simpaniz_repl_pending Tasks remaining in the replication queue.\n", .{});
        try w.print("# TYPE simpaniz_repl_pending gauge\n", .{});
        try w.print("simpaniz_repl_pending {d}\n", .{self.repl_pending.get()});

        try w.print("# HELP simpaniz_request_latency_ms Request latency histogram (ms).\n", .{});
        try w.print("# TYPE simpaniz_request_latency_ms histogram\n", .{});
        var cumulative: u64 = 0;
        for (latency_buckets_ms, 0..) |le, i| {
            cumulative += self.request_latency_ms.buckets[i].load(.monotonic);
            try w.print("simpaniz_request_latency_ms_bucket{{le=\"{d:.0}\"}} {d}\n", .{ le, cumulative });
        }
        cumulative += self.request_latency_ms.buckets[latency_buckets_ms.len].load(.monotonic);
        try w.print("simpaniz_request_latency_ms_bucket{{le=\"+Inf\"}} {d}\n", .{cumulative});
        try w.print("simpaniz_request_latency_ms_sum {d}\n", .{self.request_latency_ms.sum_ms.load(.monotonic)});
        try w.print("simpaniz_request_latency_ms_count {d}\n", .{cumulative});

        try w.print("# HELP simpaniz_uptime_seconds Process uptime in seconds.\n", .{});
        try w.print("# TYPE simpaniz_uptime_seconds gauge\n", .{});
        try w.print("simpaniz_uptime_seconds {d}\n", .{std.time.timestamp() - self.started_unix});

        return out.toOwnedSlice(allocator);
    }
};

test "registry renders" {
    const a = std.testing.allocator;
    var r = Registry{ .started_unix = std.time.timestamp() };
    r.requests_total.inc();
    r.bytes_in.add(123);
    r.request_latency_ms.observeMs(7);
    const out = try r.render(a);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "simpaniz_requests_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "simpaniz_bytes_in_total 123") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "le=\"10\"") != null);
}
