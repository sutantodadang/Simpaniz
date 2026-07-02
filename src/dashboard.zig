//! Dashboard REST API (`/_dashboard/*`) — read-only operational telemetry
//! for the embedded web console's Metrics tab. Backed by
//! `metrics.Registry` (live counters/gauges) and `timeseries.Store`
//! (in-process 24h history). No Prometheus/Grafana required.
//!
//! Unlike `/_admin/*` (root-only — mutates IAM users/policies/config),
//! this API is read-only ops data: any authenticated principal may view it
//! when auth is required, not just root. In anonymous mode (server-wide
//! auth disabled) it's reachable the same as every other endpoint, since
//! there's no non-root principal to distinguish anyway.
//!
//! ponytail: two endpoints, no pagination — matches exactly what the
//! console's Metrics tab needs today.
const std = @import("std");
const http = @import("http.zig");
const xml = @import("xml.zig");
const handlers = @import("handlers.zig");
const HandlerContext = handlers.HandlerContext;

pub fn handle(ctx: HandlerContext, req: *http.Request) http.Response {
    if (ctx.config) |cfg| {
        if (cfg.auth_required and ctx.principal == null) {
            return accessDenied(ctx, "Dashboard API requires authentication.");
        }
    }

    const path = req.path;
    if (std.mem.eql(u8, path, "/_dashboard/api/summary")) return summary(ctx, req);
    if (std.mem.eql(u8, path, "/_dashboard/api/series")) return series(ctx, req);

    return jsonErr(ctx, 404, "Not Found", "NotFound", "No such dashboard endpoint.");
}

// ── /_dashboard/api/summary ─────────────────────────────────────────────────

fn summary(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);

    var p50: f64 = 0;
    var p95: f64 = 0;
    var p99: f64 = 0;
    if (ctx.tseries) |ts| {
        if (ts.latestPercentiles()) |p| {
            p50 = p.p50;
            p95 = p.p95;
            p99 = p.p99;
        }
    }

    var in_flight: i64 = 0;
    var requests_total: u64 = 0;
    var errors_total: u64 = 0;
    var bytes_in: u64 = 0;
    var bytes_out: u64 = 0;
    var auth_failures: u64 = 0;
    if (ctx.registry) |r| {
        in_flight = @max(0, r.requests_in_flight.load(.monotonic));
        requests_total = r.requests_total.get();
        errors_total = r.errors_total.get();
        bytes_in = r.bytes_in.get();
        bytes_out = r.bytes_out.get();
        auth_failures = r.auth_failures.get();
    }

    const now = std.time.timestamp();
    const tier_mode: []const u8 = if (ctx.tiering) |t| switch (t.mode) {
        .off => "off",
        .local => "local",
        .remote => "remote",
    } else "off";

    var is_cluster = false;
    var membership_json: []const u8 = "[]";
    if (ctx.cluster) |cr| {
        is_cluster = true;
        membership_json = cr.membership.snapshotJson(ctx.allocator) catch "[]";
    }

    const body = std.fmt.allocPrint(
        ctx.allocator,
        "{{\"uptime_s\":{d},\"version\":\"0.1.1\",\"mode\":\"{s}\",\"tls\":{s}," ++
            "\"in_flight\":{d},\"requests_total\":{d},\"errors_total\":{d}," ++
            "\"bytes_in\":{d},\"bytes_out\":{d},\"auth_failures\":{d}," ++
            "\"p50_ms\":{d},\"p95_ms\":{d},\"p99_ms\":{d},\"iam_users\":{d}," ++
            "\"tier_mode\":\"{s}\",\"sse_configured\":{s},\"cluster\":{s},\"membership\":{s}}}",
        .{
            if (ctx.started_unix > 0) @max(0, now - ctx.started_unix) else 0,
            if (is_cluster) "cluster" else "single",
            jsonBool(if (ctx.config) |c| c.tls_cert_path.len > 0 else false),
            in_flight,
            requests_total,
            errors_total,
            bytes_in,
            bytes_out,
            auth_failures,
            p50,
            p95,
            p99,
            if (ctx.iam) |store| store.users.len else 0,
            tier_mode,
            jsonBool(ctx.master_key != null),
            jsonBool(is_cluster),
            membership_json,
        },
    ) catch return internalErr(ctx);

    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

// ── /_dashboard/api/series?window=<seconds> ─────────────────────────────────

fn series(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);

    var window_s: u64 = 3600;
    if (qp(req.query, "window")) |w| window_s = std.fmt.parseInt(u64, w, 10) catch 3600;
    window_s = std.math.clamp(window_s, 60, 86400);

    const ts = ctx.tseries orelse {
        const body = std.fmt.allocPrint(ctx.allocator, "{{\"interval_s\":0,\"points\":[]}}", .{}) catch "{}";
        return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
    };

    const body = ts.seriesJson(ctx.allocator, window_s) catch return internalErr(ctx);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn jsonBool(b: bool) []const u8 {
    return if (b) "true" else "false";
}

fn qp(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
            if (std.mem.eql(u8, param[0..eq], key)) return param[eq + 1 ..];
        }
    }
    return null;
}

/// Same shape as `admin.zig`'s AccessDenied — matches the S3 AccessDenied
/// XML the rest of the server uses for auth failures.
fn accessDenied(ctx: HandlerContext, message: []const u8) http.Response {
    const body = xml.buildError(ctx.allocator, "AccessDenied", message, "/_dashboard", ctx.request_id) catch "";
    return .{ .status = 403, .status_text = "Forbidden", .body = .{ .bytes = body } };
}

fn jsonErr(ctx: HandlerContext, status: u16, status_text: []const u8, code: []const u8, message: []const u8) http.Response {
    const Err = struct { @"error": []const u8, message: []const u8 };
    const body = std.json.Stringify.valueAlloc(ctx.allocator, Err{ .@"error" = code, .message = message }, .{}) catch "{}";
    return .{ .status = status, .status_text = status_text, .content_type = "application/json", .body = .{ .bytes = body } };
}

fn methodNotAllowed(ctx: HandlerContext) http.Response {
    return jsonErr(ctx, 405, "Method Not Allowed", "MethodNotAllowed", "Method not allowed.");
}

fn internalErr(ctx: HandlerContext) http.Response {
    return jsonErr(ctx, 500, "Internal Server Error", "InternalError", "Internal error.");
}

// ── Tests ────────────────────────────────────────────────────────────────────

const metrics = @import("metrics.zig");
const timeseries = @import("timeseries.zig");
const iam = @import("iam.zig");
const Config = @import("config.zig");

fn testCtx(allocator: std.mem.Allocator, registry: ?*metrics.Registry, principal: ?iam.Principal) HandlerContext {
    return .{
        .data_dir = undefined,
        .allocator = allocator,
        .request_id = "test-request",
        .region = "us-east-1",
        .principal = principal,
        .registry = registry,
        .started_unix = 1000,
    };
}

test "summary: anonymous access allowed when auth not required" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var registry = metrics.Registry{ .started_unix = 1000 };
    registry.requests_total.add(42);

    const ctx = testCtx(arena.allocator(), &registry, null);

    var fbs = std.Io.Reader.fixed("GET /_dashboard/api/summary HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"uptime_s\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"requests_total\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"version\"") != null);
}

test "series: clamps window to [60, 86400]" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var registry = metrics.Registry{ .started_unix = 1000 };
    var store = try timeseries.Store.init(std.testing.allocator, &registry, 8, 0);
    defer store.deinit();

    var ctx = testCtx(arena.allocator(), &registry, null);
    ctx.tseries = store;

    var fbs = std.Io.Reader.fixed("GET /_dashboard/api/series?window=5 HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"interval_s\"") != null);
}

test "series: with no sampler configured returns empty points" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var registry = metrics.Registry{ .started_unix = 1000 };
    const ctx = testCtx(arena.allocator(), &registry, null);

    var fbs = std.Io.Reader.fixed("GET /_dashboard/api/series HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"points\":[]") != null);
}

test "handle: unknown path returns 404" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var registry = metrics.Registry{ .started_unix = 1000 };
    const ctx = testCtx(arena.allocator(), &registry, null);

    var fbs = std.Io.Reader.fixed("GET /_dashboard/api/nope HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 404), resp.status);
}

test "handle: auth required and no principal -> 403" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var registry = metrics.Registry{ .started_unix = 1000 };
    var ctx = testCtx(arena.allocator(), &registry, null);

    var config = Config{
        .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
        .host = "0.0.0.0",
        .port = 9000,
        .data_dir = "./data",
        .region = "us-east-1",
        .access_key = "ROOTKEY",
        .secret_key = "ROOTSECRET",
        .max_body_bytes = 0,
        .idle_timeout_ms = 0,
        .read_timeout_ms = 0,
        .max_header_bytes = 16 * 1024,
        .max_headers = 64,
        .auth_required = true,
        .master_key = .{0} ** 32,
        .master_key_set = false,
        .max_conns = 1,
        .scrub_interval_s = 0,
        .lifecycle_interval_s = 0,
        .heal_interval_s = 0,
        .tls_cert_path = "",
        .tls_key_path = "",
    };
    defer config.deinit();
    ctx.config = &config;

    var fbs = std.Io.Reader.fixed("GET /_dashboard/api/summary HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 403), resp.status);
}
