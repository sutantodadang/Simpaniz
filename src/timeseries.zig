//! In-process metric history: a fixed-capacity ring buffer of periodic
//! samples, sampled from `metrics.Registry` on a background thread. Powers
//! the embedded web console's Metrics tab (`dashboard.zig`) without a
//! Prometheus/Grafana dependency.
//!
//! ponytail: history lost on restart; disk ring later, if ever needed.
const std = @import("std");
const Allocator = std.mem.Allocator;
const metrics = @import("metrics.zig");

/// Default sampling period in seconds. Overridable via
/// `SIMPANIZ_METRICS_SAMPLE_S` (0 disables the sampler entirely — the
/// dashboard API still answers, `/summary` from live registry counters,
/// `/series` with an empty point list).
pub const sample_interval_s: u32 = 10;

/// Ring capacity for the default sampling period: 24h of history at 10s
/// resolution (8640 points × ~80 bytes ≈ 690 KiB).
pub const default_capacity: usize = 8640;

/// One bucket count per histogram bucket, including the `+Inf` overflow.
const num_buckets = metrics.latency_buckets_ms.len + 1;

pub const Point = struct {
    t_unix: i64,
    requests_total: u64,
    errors_total: u64,
    bytes_in: u64,
    bytes_out: u64,
    auth_failures: u64,
    in_flight: u64,
    lat_p50_ms: f64,
    lat_p95_ms: f64,
    lat_p99_ms: f64,
};

const Percentiles = struct { p50: f64, p95: f64, p99: f64 };

/// Read `SIMPANIZ_METRICS_SAMPLE_S`, falling back to `sample_interval_s`.
pub fn readSampleIntervalEnv(gpa: Allocator) u32 {
    const s = std.process.getEnvVarOwned(gpa, "SIMPANIZ_METRICS_SAMPLE_S") catch return sample_interval_s;
    defer gpa.free(s);
    return std.fmt.parseInt(u32, s, 10) catch sample_interval_s;
}

pub const Store = struct {
    allocator: Allocator,
    registry: *metrics.Registry,
    /// Fixed-size backing array; `write_idx`/`count` track the logical ring.
    ring: []Point,
    write_idx: usize = 0,
    count: usize = 0,
    mutex: std.Thread.Mutex = .{},
    sampler: ?std.Thread = null,
    running: std.atomic.Value(bool) = .{ .raw = false },
    interval_s: u32,
    /// Histogram bucket counts as of the previous sample — used to derive
    /// the windowed (per-interval) percentiles from the delta, since the
    /// registry's histogram is cumulative-since-boot.
    prev_buckets: [num_buckets]u64 = @splat(0),
    has_prev: bool = false,
    /// Carried forward when a sample interval sees zero new observations
    /// (delta all-zero), so the series doesn't dip to 0ms artificially.
    prev_percentiles: Percentiles = .{ .p50 = 0, .p95 = 0, .p99 = 0 },

    pub fn init(gpa: Allocator, registry: *metrics.Registry, capacity: usize, interval_s: u32) !*Store {
        const s = try gpa.create(Store);
        errdefer gpa.destroy(s);
        const ring = try gpa.alloc(Point, capacity);
        s.* = .{
            .allocator = gpa,
            .registry = registry,
            .ring = ring,
            .interval_s = interval_s,
        };
        return s;
    }

    /// Spawns the sampler thread. No-op if `interval_s == 0` (sampler
    /// disabled) or already started.
    pub fn start(self: *Store) !void {
        if (self.interval_s == 0) return;
        if (self.sampler != null) return;
        self.running.store(true, .seq_cst);
        self.sampler = std.Thread.spawn(.{}, samplerLoop, .{self}) catch |e| {
            self.running.store(false, .seq_cst);
            return e;
        };
    }

    /// Signal the sampler to stop and join it. Safe to call more than once.
    pub fn shutdown(self: *Store) void {
        self.running.store(false, .seq_cst);
        if (self.sampler) |t| {
            t.join();
            self.sampler = null;
        }
    }

    pub fn deinit(self: *Store) void {
        self.shutdown();
        self.allocator.free(self.ring);
        self.allocator.destroy(self);
    }

    fn samplerLoop(self: *Store) void {
        const interval_ns = @as(u64, self.interval_s) * std.time.ns_per_s;
        while (self.running.load(.seq_cst)) {
            std.Thread.sleep(interval_ns);
            if (!self.running.load(.seq_cst)) break;
            self.recordSample(std.time.timestamp());
        }
    }

    /// Snapshot the registry (atomic reads only, no locks held on it) and
    /// push one point. Exposed at package-private visibility so tests can
    /// drive deterministic samples without a real thread/clock.
    fn recordSample(self: *Store, t_unix: i64) void {
        const r = self.registry;

        var cur_buckets: [num_buckets]u64 = undefined;
        for (0..num_buckets) |i| cur_buckets[i] = r.request_latency_ms.buckets[i].load(.monotonic);

        if (histogramDeltaPercentiles(cur_buckets, self.prev_buckets, self.has_prev)) |p| {
            self.prev_percentiles = p;
        }
        self.prev_buckets = cur_buckets;
        self.has_prev = true;

        const in_flight_raw = r.requests_in_flight.load(.monotonic);
        const point = Point{
            .t_unix = t_unix,
            .requests_total = r.requests_total.get(),
            .errors_total = r.errors_total.get(),
            .bytes_in = r.bytes_in.get(),
            .bytes_out = r.bytes_out.get(),
            .auth_failures = r.auth_failures.get(),
            .in_flight = if (in_flight_raw > 0) @intCast(in_flight_raw) else 0,
            .lat_p50_ms = self.prev_percentiles.p50,
            .lat_p95_ms = self.prev_percentiles.p95,
            .lat_p99_ms = self.prev_percentiles.p99,
        };
        self.push(point);
    }

    fn push(self: *Store, pt: Point) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ring[self.write_idx] = pt;
        self.write_idx = (self.write_idx + 1) % self.ring.len;
        if (self.count < self.ring.len) self.count += 1;
    }

    /// Percentiles from the most recent sample, or null if no sample has
    /// been recorded yet.
    pub fn latestPercentiles(self: *Store) ?Percentiles {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return null;
        const idx = (self.write_idx + self.ring.len - 1) % self.ring.len;
        const pt = self.ring[idx];
        return .{ .p50 = pt.lat_p50_ms, .p95 = pt.lat_p95_ms, .p99 = pt.lat_p99_ms };
    }

    const SeriesPoint = struct {
        t: i64,
        rps: f64,
        eps: f64,
        in_bps: f64,
        out_bps: f64,
        inflight: u64,
        p50: f64,
        p95: f64,
        p99: f64,
    };

    const Series = struct {
        interval_s: u32,
        points: []const SeriesPoint,
    };

    /// Rates (rps/eps/bps) are derived server-side from consecutive
    /// counter deltas so the browser stays dumb (no cumulative-vs-rate
    /// logic in JS). A counter reset (process restart) shows up as
    /// `cur < prev`, which is clamped to a 0 rate rather than going
    /// negative.
    pub fn seriesJson(self: *Store, allocator: Allocator, window_s: u64) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count == 0) {
            return std.json.Stringify.valueAlloc(allocator, Series{ .interval_s = self.interval_s, .points = &.{} }, .{});
        }

        var list = std.ArrayList(SeriesPoint){};
        defer list.deinit(allocator);

        const start_idx: usize = if (self.count < self.ring.len) 0 else self.write_idx;
        const latest_t = self.ring[(start_idx + self.count - 1) % self.ring.len].t_unix;
        const cutoff = latest_t - @as(i64, @intCast(window_s));

        var prev: ?Point = null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (start_idx + i) % self.ring.len;
            const cur = self.ring[idx];

            var rps: f64 = 0;
            var eps: f64 = 0;
            var in_bps: f64 = 0;
            var out_bps: f64 = 0;
            if (prev) |p| {
                const dt = cur.t_unix - p.t_unix;
                if (dt > 0) {
                    rps = rateOf(cur.requests_total, p.requests_total, dt);
                    eps = rateOf(cur.errors_total, p.errors_total, dt);
                    in_bps = rateOf(cur.bytes_in, p.bytes_in, dt);
                    out_bps = rateOf(cur.bytes_out, p.bytes_out, dt);
                }
            }
            prev = cur;

            if (cur.t_unix >= cutoff) {
                try list.append(allocator, .{
                    .t = cur.t_unix,
                    .rps = rps,
                    .eps = eps,
                    .in_bps = in_bps,
                    .out_bps = out_bps,
                    .inflight = cur.in_flight,
                    .p50 = cur.lat_p50_ms,
                    .p95 = cur.lat_p95_ms,
                    .p99 = cur.lat_p99_ms,
                });
            }
        }

        return std.json.Stringify.valueAlloc(allocator, Series{ .interval_s = self.interval_s, .points = list.items }, .{});
    }
};

fn rateOf(cur: u64, prev: u64, dt: i64) f64 {
    if (cur < prev) return 0; // counter reset (process restart) — clamp, don't go negative
    const delta = cur - prev;
    return @as(f64, @floatFromInt(delta)) / @as(f64, @floatFromInt(dt));
}

/// Percentiles derived from the delta between two histogram bucket-count
/// snapshots (i.e. only observations since `prev`), using the same linear
/// interpolation Prometheus's `histogram_quantile` uses. Returns null when
/// there's no previous snapshot yet or zero observations in the delta (in
/// which case the caller should carry forward the last known percentiles).
fn histogramDeltaPercentiles(cur: [num_buckets]u64, prev: [num_buckets]u64, has_prev: bool) ?Percentiles {
    if (!has_prev) return null;

    var deltas: [num_buckets]u64 = undefined;
    var total: u64 = 0;
    for (0..num_buckets) |i| {
        const d = if (cur[i] >= prev[i]) cur[i] - prev[i] else 0; // counter reset clamp
        deltas[i] = d;
        total += d;
    }
    if (total == 0) return null;

    var cum: [num_buckets]u64 = undefined;
    var running: u64 = 0;
    for (0..num_buckets) |i| {
        running += deltas[i];
        cum[i] = running;
    }

    return Percentiles{
        .p50 = percentileFromCumulative(cum, 0.50),
        .p95 = percentileFromCumulative(cum, 0.95),
        .p99 = percentileFromCumulative(cum, 0.99),
    };
}

fn percentileFromCumulative(cum: [num_buckets]u64, frac: f64) f64 {
    const total = cum[num_buckets - 1];
    const target = frac * @as(f64, @floatFromInt(total));

    var idx: usize = 0;
    while (idx < num_buckets) : (idx += 1) {
        if (@as(f64, @floatFromInt(cum[idx])) >= target) break;
    }
    if (idx >= num_buckets) idx = num_buckets - 1;

    const bucket_start: f64 = if (idx == 0) 0 else metrics.latency_buckets_ms[idx - 1];
    // Last bucket is the `+Inf` overflow — no upper bound to interpolate
    // into, so clamp to the last finite edge.
    if (idx == metrics.latency_buckets_ms.len) return bucket_start;

    const bucket_end: f64 = metrics.latency_buckets_ms[idx];
    const rank_before: f64 = if (idx == 0) 0 else @floatFromInt(cum[idx - 1]);
    const count_in_bucket: f64 = @as(f64, @floatFromInt(cum[idx])) - rank_before;
    if (count_in_bucket <= 0) return bucket_end;

    const fraction = (target - rank_before) / count_in_bucket;
    return bucket_start + fraction * (bucket_end - bucket_start);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "ring wraps at capacity, keeps most recent points in order" {
    const a = std.testing.allocator;
    var registry = metrics.Registry{ .started_unix = 0 };
    const store = try Store.init(a, &registry, 4, 0); // interval 0: no sampler thread
    defer store.deinit();

    var t: i64 = 1000;
    var i: u64 = 0;
    while (i < 6) : (i += 1) {
        store.push(.{
            .t_unix = t,
            .requests_total = i,
            .errors_total = 0,
            .bytes_in = 0,
            .bytes_out = 0,
            .auth_failures = 0,
            .in_flight = 0,
            .lat_p50_ms = 0,
            .lat_p95_ms = 0,
            .lat_p99_ms = 0,
        });
        t += 10;
    }

    try std.testing.expectEqual(@as(usize, 4), store.count);

    const json = try store.seriesJson(a, 100_000);
    defer a.free(json);

    const Parsed = struct { interval_s: u32, points: []struct { t: i64, rps: f64, eps: f64, in_bps: f64, out_bps: f64, inflight: u64, p50: f64, p95: f64, p99: f64 } };
    const parsed = try std.json.parseFromSlice(Parsed, a, json, .{});
    defer parsed.deinit();

    // Only the last 4 pushes (requests_total 2..5, t=1020..1050) survive.
    try std.testing.expectEqual(@as(usize, 4), parsed.value.points.len);
    try std.testing.expectEqual(@as(i64, 1020), parsed.value.points[0].t);
    try std.testing.expectEqual(@as(i64, 1050), parsed.value.points[3].t);
}

test "seriesJson derives per-second rates and clamps counter resets" {
    const a = std.testing.allocator;
    var registry = metrics.Registry{ .started_unix = 0 };
    const store = try Store.init(a, &registry, 8, 0);
    defer store.deinit();

    store.push(.{ .t_unix = 0, .requests_total = 0, .errors_total = 0, .bytes_in = 0, .bytes_out = 0, .auth_failures = 0, .in_flight = 0, .lat_p50_ms = 0, .lat_p95_ms = 0, .lat_p99_ms = 0 });
    store.push(.{ .t_unix = 10, .requests_total = 100, .errors_total = 0, .bytes_in = 0, .bytes_out = 0, .auth_failures = 0, .in_flight = 0, .lat_p50_ms = 0, .lat_p95_ms = 0, .lat_p99_ms = 0 });
    // Process restart: counter resets to a smaller value.
    store.push(.{ .t_unix = 20, .requests_total = 5, .errors_total = 0, .bytes_in = 0, .bytes_out = 0, .auth_failures = 0, .in_flight = 0, .lat_p50_ms = 0, .lat_p95_ms = 0, .lat_p99_ms = 0 });

    const json = try store.seriesJson(a, 1_000_000);
    defer a.free(json);

    const Parsed = struct { interval_s: u32, points: []struct { t: i64, rps: f64, eps: f64, in_bps: f64, out_bps: f64, inflight: u64, p50: f64, p95: f64, p99: f64 } };
    const parsed = try std.json.parseFromSlice(Parsed, a, json, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 3), parsed.value.points.len);
    try std.testing.expectApproxEqAbs(@as(f64, 0), parsed.value.points[0].rps, 1e-9); // no prev point
    try std.testing.expectApproxEqAbs(@as(f64, 10), parsed.value.points[1].rps, 1e-9); // 100/10s
    try std.testing.expectApproxEqAbs(@as(f64, 0), parsed.value.points[2].rps, 1e-9); // reset clamp
}

test "percentiles from histogram delta match hand-computed interpolation" {
    // Bucket edges: 1,5,10,25,50,100,250,500,1000,2500,5000,10000,+Inf (13 total).
    // Deltas: 0 in <=1, 2 in <=5, 3 in <=10, rest 0. total=5.
    var prev: [num_buckets]u64 = @splat(0);
    var cur: [num_buckets]u64 = @splat(0);
    cur[1] = 2; // <=5 bucket count (non-cumulative)
    cur[2] = 3; // <=10 bucket count
    // cumulative equivalents as stored in metrics.Histogram.buckets are
    // actually non-cumulative per-bucket counts (see metrics.zig render());
    // histogramDeltaPercentiles takes the same non-cumulative shape.
    _ = &prev;

    const p = histogramDeltaPercentiles(cur, prev, true).?;
    // target p50 = 2.5 -> falls in bucket idx=2 (5..10], rank_before=2, count=3
    // fraction = 0.5/3 = 0.16667 -> 5 + 0.16667*5 = 5.8333
    try std.testing.expectApproxEqAbs(@as(f64, 5.8333333), p.p50, 1e-4);
    // target p95 = 4.75 -> fraction = 2.75/3 = 0.91667 -> 5 + 4.5833 = 9.5833
    try std.testing.expectApproxEqAbs(@as(f64, 9.5833333), p.p95, 1e-4);
    // target p99 = 4.95 -> fraction = 2.95/3 = 0.98333 -> 5 + 4.9167 = 9.9167
    try std.testing.expectApproxEqAbs(@as(f64, 9.9166666), p.p99, 1e-4);
}

test "histogramDeltaPercentiles returns null with no prior snapshot or zero delta" {
    const zeros: [num_buckets]u64 = @splat(0);
    try std.testing.expect(histogramDeltaPercentiles(zeros, zeros, false) == null);
    try std.testing.expect(histogramDeltaPercentiles(zeros, zeros, true) == null);
}

test "seriesJson window filtering keeps only recent points" {
    const a = std.testing.allocator;
    var registry = metrics.Registry{ .started_unix = 0 };
    const store = try Store.init(a, &registry, 16, 0);
    defer store.deinit();

    var t: i64 = 0;
    while (t <= 100) : (t += 10) {
        store.push(.{ .t_unix = t, .requests_total = @intCast(t), .errors_total = 0, .bytes_in = 0, .bytes_out = 0, .auth_failures = 0, .in_flight = 0, .lat_p50_ms = 0, .lat_p95_ms = 0, .lat_p99_ms = 0 });
    }
    // Latest t=100. window=25 -> cutoff=75 -> keep t in {80,90,100}.
    const json = try store.seriesJson(a, 25);
    defer a.free(json);

    const Parsed = struct { interval_s: u32, points: []struct { t: i64, rps: f64, eps: f64, in_bps: f64, out_bps: f64, inflight: u64, p50: f64, p95: f64, p99: f64 } };
    const parsed = try std.json.parseFromSlice(Parsed, a, json, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 3), parsed.value.points.len);
    try std.testing.expectEqual(@as(i64, 80), parsed.value.points[0].t);
    try std.testing.expectEqual(@as(i64, 100), parsed.value.points[2].t);
}

test "recordSample end-to-end: pushes a point from live registry state" {
    const a = std.testing.allocator;
    var registry = metrics.Registry{ .started_unix = 0 };
    registry.requests_total.add(5);
    registry.request_latency_ms.observeMs(3);

    const store = try Store.init(a, &registry, 4, 0);
    defer store.deinit();

    store.recordSample(1);
    // First sample establishes the baseline; percentiles are 0 until a
    // second sample sees a delta.
    try std.testing.expectEqual(@as(usize, 1), store.count);

    registry.requests_total.add(2);
    registry.request_latency_ms.observeMs(7);
    store.recordSample(2);
    try std.testing.expectEqual(@as(usize, 2), store.count);

    const p = store.latestPercentiles().?;
    try std.testing.expect(p.p50 > 0); // one obs at 7ms since prev sample
}
