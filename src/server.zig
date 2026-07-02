//! TCP server with thread-per-connection HTTP handling, request id generation,
//! structured access logs, /metrics endpoint, signal-based graceful shutdown,
//! and SigV4 authentication enforcement (when configured).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const http = @import("http.zig");
const router = @import("router.zig");
const handlers = @import("handlers.zig");
const Config = @import("config.zig");
const auth = @import("auth.zig");
const util = @import("util.zig");
const metrics = @import("metrics.zig");
const storage = @import("storage.zig");
const cluster = @import("cluster.zig");
const ui = @import("ui.zig");
const iam = @import("iam.zig");
const events = @import("events.zig");
const tls_server = @import("tls_server.zig");
const index_mod = @import("index.zig");

const DaemonCtx = struct {
    data_dir: std.fs.Dir,
    gpa: Allocator,
    registry: *metrics.Registry,
    interval_ns: u64,
    /// Only set for the lifecycle sweeper — background expirations must also
    /// remove the expired key from the persistent listing index.
    index: ?*index_mod.Manager = null,
};

const HealDaemonCtx = struct {
    rt: *cluster.ClusterRuntime,
    gpa: Allocator,
    registry: *metrics.Registry,
    interval_ns: u64,
    stats: cluster.HealDaemon.Stats = .{},
};

fn healLoop(c: *HealDaemonCtx) void {
    while (!shutdown_requested.load(.seq_cst)) {
        std.Thread.sleep(c.interval_ns);
        if (shutdown_requested.load(.seq_cst)) break;
        cluster.HealDaemon.runOnce(c.rt, c.gpa, &c.stats) catch |e| {
            std.log.warn("heal run failed: {}", .{e});
            continue;
        };
        const repaired = c.stats.repaired_total.load(.monotonic);
        c.registry.heal_repaired_total.set(repaired);
        std.log.info("heal: total_repaired={d}", .{repaired});
    }
}

const RebalanceDaemonCtx = struct {
    rt: *cluster.ClusterRuntime,
    gpa: Allocator,
    /// Poll tick for noticing a membership generation change; the actual
    /// sweep only runs when `interval_s` has elapsed OR the generation
    /// moved since the last sweep, whichever comes first.
    poll_interval_ns: u64 = 5 * std.time.ns_per_s,
    interval_ns: u64,
    last_generation: u64 = 0,
    last_sweep_ns: i128 = 0,
};

fn rebalanceLoop(c: *RebalanceDaemonCtx) void {
    while (!shutdown_requested.load(.seq_cst)) {
        std.Thread.sleep(c.poll_interval_ns);
        if (shutdown_requested.load(.seq_cst)) break;

        const gen = c.rt.membership.generation.load(.monotonic);
        const now_ns = std.time.nanoTimestamp();
        const due_by_interval = c.interval_ns > 0 and (now_ns - c.last_sweep_ns) >= @as(i128, @intCast(c.interval_ns));
        const due_by_membership_change = gen != c.last_generation;
        if (!due_by_interval and !due_by_membership_change) continue;

        c.last_generation = gen;
        c.last_sweep_ns = now_ns;
        const stats = cluster.RebalanceDaemon.runOnce(c.rt, c.gpa) catch |e| {
            std.log.warn("rebalance run failed: {}", .{e});
            continue;
        };
        if (stats.moved > 0 or stats.errors > 0) {
            std.log.info("rebalance: scanned={d} moved={d} errors={d}", .{ stats.scanned, stats.moved, stats.errors });
        }
    }
}

fn scrubLoop(c: *DaemonCtx) void {
    while (!shutdown_requested.load(.seq_cst)) {
        std.Thread.sleep(c.interval_ns);
        if (shutdown_requested.load(.seq_cst)) break;
        const stats = storage.scrubOnce(c.data_dir, c.gpa) catch |e| {
            std.log.warn("scrub run failed: {}", .{e});
            continue;
        };
        c.registry.bitrot_ok_total.add(stats.ok);
        c.registry.bitrot_errors_total.add(stats.failed);
        std.log.info("scrub: ok={d} failed={d} skipped={d}", .{ stats.ok, stats.failed, stats.skipped });
    }
}

fn lifecycleLoop(c: *DaemonCtx) void {
    while (!shutdown_requested.load(.seq_cst)) {
        std.Thread.sleep(c.interval_ns);
        if (shutdown_requested.load(.seq_cst)) break;
        const now: i128 = std.time.nanoTimestamp();
        const stats = storage.sweepLifecycle(c.data_dir, c.gpa, now, c.index) catch |e| {
            std.log.warn("lifecycle sweep failed: {}", .{e});
            continue;
        };
        c.registry.lifecycle_expirations_total.add(stats.expired);
        if (stats.expired > 0) std.log.info("lifecycle: expired={d}", .{stats.expired});
    }
}

// Global shutdown flag (set by signal handler).
var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Bounded-concurrency permit. accept() blocks while at the limit; on overflow
/// of pending accepts the kernel SYN backlog handles further pressure.
const Permits = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    available: u32,

    fn acquire(self: *Permits) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.available == 0) self.cond.wait(&self.mutex);
        self.available -= 1;
    }

    fn release(self: *Permits) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.available += 1;
        self.cond.signal();
    }
};

fn setSocketTimeouts(handle: std.posix.socket_t, ms: u32) void {
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

pub const Context = struct {
    config: *const Config,
    data_dir: std.fs.Dir,
    gpa: Allocator,
    registry: *metrics.Registry,
    cluster: ?*cluster.ClusterRuntime = null,
    iam: *iam.Store,
    notifier: ?*events.Notifier = null,
    tls: ?*tls_server.ServerContext = null,
    /// Persistent object-listing index, single-node only (null in cluster
    /// mode — cluster listing still walks the shard-local metadata).
    index: ?*index_mod.Manager = null,
};

pub fn requestShutdown() void {
    shutdown_requested.store(true, .seq_cst);
}

fn sigHandler(_: c_int) callconv(.c) void {
    requestShutdown();
}

pub fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) return;
    const posix = std.posix;
    var act = posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);
}

pub fn start(ctx: Context) !void {
    const address = std.net.Address.parseIp(ctx.config.host, ctx.config.port) catch |err| {
        std.log.err("Bad listen address {s}:{d}: {}", .{ ctx.config.host, ctx.config.port, err });
        return err;
    };

    var server = address.listen(.{ .reuse_address = true }) catch |err| {
        std.log.err("Listen failed on {s}:{d}: {}", .{ ctx.config.host, ctx.config.port, err });
        return err;
    };
    defer server.deinit();

    var permits: Permits = .{ .available = ctx.config.max_conns };

    var addr_buf: [64]u8 = undefined;
    std.log.info("Simpaniz listening on {s} (region={s}, auth_required={}, max_conns={d})", .{
        ctx.config.listenAddress(&addr_buf),
        ctx.config.region,
        ctx.config.auth_required,
        ctx.config.max_conns,
    });

    if (ctx.config.scrub_interval_s > 0) {
        if (ctx.gpa.create(DaemonCtx)) |dc| {
            dc.* = .{ .data_dir = ctx.data_dir, .gpa = ctx.gpa, .registry = ctx.registry, .interval_ns = ctx.config.scrub_interval_s * std.time.ns_per_s };
            if (std.Thread.spawn(.{}, scrubLoop, .{dc})) |t| {
                t.detach();
                std.log.info("scrub daemon enabled (interval={d}s)", .{ctx.config.scrub_interval_s});
            } else |e| {
                std.log.warn("scrub daemon spawn failed: {}", .{e});
                ctx.gpa.destroy(dc);
            }
        } else |e| std.log.warn("scrub daemon alloc failed: {}", .{e});
    }
    if (ctx.config.lifecycle_interval_s > 0) {
        if (ctx.gpa.create(DaemonCtx)) |dc| {
            dc.* = .{ .data_dir = ctx.data_dir, .gpa = ctx.gpa, .registry = ctx.registry, .interval_ns = ctx.config.lifecycle_interval_s * std.time.ns_per_s, .index = ctx.index };
            if (std.Thread.spawn(.{}, lifecycleLoop, .{dc})) |t| {
                t.detach();
                std.log.info("lifecycle daemon enabled (interval={d}s)", .{ctx.config.lifecycle_interval_s});
            } else |e| {
                std.log.warn("lifecycle daemon spawn failed: {}", .{e});
                ctx.gpa.destroy(dc);
            }
        } else |e| std.log.warn("lifecycle daemon alloc failed: {}", .{e});
    }
    if (ctx.cluster != null and ctx.config.heal_interval_s > 0) {
        if (ctx.gpa.create(HealDaemonCtx)) |dc| {
            dc.* = .{
                .rt = ctx.cluster.?,
                .gpa = ctx.gpa,
                .registry = ctx.registry,
                .interval_ns = ctx.config.heal_interval_s * std.time.ns_per_s,
            };
            if (std.Thread.spawn(.{}, healLoop, .{dc})) |t| {
                t.detach();
                std.log.info("heal daemon enabled (interval={d}s)", .{ctx.config.heal_interval_s});
            } else |e| {
                std.log.warn("heal daemon spawn failed: {}", .{e});
                ctx.gpa.destroy(dc);
            }
        } else |e| std.log.warn("heal daemon alloc failed: {}", .{e});
    }
    if (ctx.cluster) |cr| {
        // Membership prober: always on in cluster mode — this is the
        // active health check that flips a killed node to `down` within
        // the probe interval, and the gossip piggyback that lets nodes
        // discover peers they didn't statically configure.
        cr.startMembership() catch |e| std.log.warn("membership prober start failed: {}", .{e});
        cr.joinCluster();

        // Rebalance sweep runs unconditionally too: it self-throttles on
        // `SIMPANIZ_REBALANCE_INTERVAL_S` for periodic sweeps but always
        // reacts to a membership generation change (node joined/went
        // down/came back), which is what makes "add a 4th node" actually
        // redistribute shards without a restart.
        if (ctx.gpa.create(RebalanceDaemonCtx)) |dc| {
            dc.* = .{
                .rt = cr,
                .gpa = ctx.gpa,
                .interval_ns = cr.config.rebalance_interval_s * std.time.ns_per_s,
                .last_generation = cr.membership.generation.load(.monotonic),
                .last_sweep_ns = std.time.nanoTimestamp(),
            };
            if (std.Thread.spawn(.{}, rebalanceLoop, .{dc})) |t| {
                t.detach();
                std.log.info("rebalance daemon enabled (interval={d}s)", .{cr.config.rebalance_interval_s});
            } else |e| {
                std.log.warn("rebalance daemon spawn failed: {}", .{e});
                ctx.gpa.destroy(dc);
            }
        } else |e| std.log.warn("rebalance daemon alloc failed: {}", .{e});
    }

    while (!shutdown_requested.load(.seq_cst)) {
        permits.acquire();
        const conn = server.accept() catch |err| {
            permits.release();
            if (shutdown_requested.load(.seq_cst)) break;
            std.log.err("Accept error: {}", .{err});
            continue;
        };
        setSocketTimeouts(conn.stream.handle, ctx.config.read_timeout_ms);
        const thread = std.Thread.spawn(.{}, handleConnection, .{ conn.stream, ctx, &permits }) catch |err| {
            std.log.err("Thread spawn error: {}", .{err});
            conn.stream.close();
            permits.release();
            continue;
        };
        thread.detach();
    }
    std.log.info("Shutdown requested, draining...", .{});
}

fn handleConnection(stream: std.net.Stream, ctx: Context, permits: *Permits) void {
    defer permits.release();
    defer stream.close();

    if (ctx.tls) |tsrv| {
        handleTlsConnection(stream, ctx, tsrv);
        return;
    }

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(&read_buf);
    var sw = stream.writer(&write_buf);

    serveHttp(sr.interface(), &sw.interface, ctx);
}

/// TLS-terminated connection path: performs the server-side TLS 1.3
/// handshake, then runs the same HTTP request loop as the plaintext path
/// over the decrypted `Io.Reader`/`Io.Writer` the handshake exposes.
fn handleTlsConnection(stream: std.net.Stream, ctx: Context, tsrv: *tls_server.ServerContext) void {
    var net_read_buf: [tls_server.Connection.min_net_buffer_len]u8 = undefined;
    var net_write_buf: [tls_server.Connection.min_net_buffer_len]u8 = undefined;
    var plain_read_buf: [tls_server.Connection.min_plain_read_buffer_len]u8 = undefined;
    var plain_write_buf: [64 * 1024]u8 = undefined;

    var conn = tls_server.Connection.accept(
        stream,
        tsrv,
        &net_read_buf,
        &net_write_buf,
        &plain_read_buf,
        &plain_write_buf,
    ) catch |err| {
        std.log.debug("tls handshake failed: {}", .{err});
        return;
    };
    defer conn.close();

    serveHttp(&conn.reader, &conn.writer, ctx);
}

/// Shared HTTP request-serving loop, driven over either a plaintext or a
/// TLS-decrypted `Io.Reader`/`Io.Writer` pair.
fn serveHttp(in: *Io.Reader, out: *Io.Writer, ctx: Context) void {
    while (!shutdown_requested.load(.seq_cst)) {
        const start_ns = std.time.nanoTimestamp();
        _ = ctx.registry.requests_in_flight.fetchAdd(1, .monotonic);
        defer _ = ctx.registry.requests_in_flight.fetchSub(1, .monotonic);

        var request = http.parseRequest(in, ctx.gpa, .{
            .max_header_bytes = ctx.config.max_header_bytes,
            .max_headers = ctx.config.max_headers,
        }) catch |err| {
            // Quietly close on EOF / closed-connection (common with curl one-shot).
            if (err == error.ReadFailed) return;
            handleParseError(out, err);
            return;
        };
        defer request.deinit();

        // Generate request id.
        var rid_bytes: [16]u8 = undefined;
        util.newRequestId(&rid_bytes);
        var rid_hex: [32]u8 = undefined;
        util.hexEncodeBuf(&rid_bytes, &rid_hex);
        const request_id = request.arena.allocator().dupe(u8, &rid_hex) catch &rid_hex;

        // Enforce body size limit (single-request).
        if (request.content_length > ctx.config.max_body_bytes) {
            ctx.registry.errors_total.inc();
            http.writeError(out, 413, "Payload Too Large", "");
            out.flush() catch return;
            return;
        }

        // Web console assets — public static bundle, bypasses SigV4. The S3
        // calls the console makes from the browser are still signed and go
        // through normal auth.
        if (ui.matches(request.path)) {
            const resp = ui.serve(request.path);
            writeAndLog(out, &request, &resp, request_id, start_ns, ctx);
            drainBody(&request) catch return;
            continue;
        }

        // Cluster internal endpoint — bypass SigV4, authenticated via shared
        // secret in X-Simpaniz-Cluster-Auth header.
        if (ctx.cluster != null and cluster.isInternalPath(request.path)) {
            const cr = ctx.cluster.?;
            const resp = cluster.internalHandler(&request, ctx.data_dir, cr.config.cluster_secret, ctx.config.max_body_bytes, cr.membership);
            writeAndLog(out, &request, &resp, request_id, start_ns, ctx);
            drainBody(&request) catch return;
            continue;
        }

        // Auth (best-effort SigV4 verification when configured).
        var principal: ?iam.Principal = null;
        if (ctx.config.auth_required) {
            principal = verifyRequestAuth(&request, ctx.config, ctx.iam) catch null;
            if (principal == null) {
                ctx.registry.auth_failures.inc();
                writeAuthError(out, request_id);
                out.flush() catch return;
                drainBody(&request) catch {};
                continue;
            }
        }

        // Policy enforcement (skip root; skip metrics/health/console/cluster
        // paths, which are either bypassed above or exempt below). Runs even
        // when auth is not required so anonymous mode still honors an
        // explicit bucket-policy Deny.
        if (!isExemptPath(request.path)) {
            var b: []const u8 = "";
            var k: []const u8 = "";
            router.splitBucketKey(&request, &b, &k);
            const action = iam.mapAction(request.method, b, k, request.query);
            const pol = if (b.len > 0)
                storage.getBucketPolicy(ctx.data_dir, request.arena.allocator(), b) catch null
            else
                null;
            const allowed = iam.authorize(ctx.iam, pol, principal, action, b, k, request.arena.allocator());
            if (!allowed) {
                ctx.registry.auth_failures.inc();
                writeAccessDenied(out, request_id);
                out.flush() catch return;
                drainBody(&request) catch {};
                continue;
            }
        }

        const handler_ctx = handlers.HandlerContext{
            .data_dir = ctx.data_dir,
            .allocator = request.arena.allocator(),
            .request_id = request_id,
            .region = ctx.config.region,
            .master_key = if (ctx.config.master_key_set) &ctx.config.master_key else null,
            .cluster = ctx.cluster,
            .max_body_bytes = ctx.config.max_body_bytes,
            .notifier = ctx.notifier,
            .index = ctx.index,
        };

        // Special: /metrics (needs registry).
        if (std.mem.eql(u8, request.path, "/metrics") and request.method == .GET) {
            // Snapshot cluster transport counters before render so the
            // exposition shows current values, not stale ones.
            if (ctx.cluster) |cr| {
                ctx.registry.cluster_peer_unreachable.set(cr.metrics.peer_unreachable.load(.monotonic));
                ctx.registry.cluster_shard_put_ok.set(cr.metrics.shard_put_ok.load(.monotonic));
                ctx.registry.cluster_shard_put_err.set(cr.metrics.shard_put_err.load(.monotonic));
                ctx.registry.cluster_shard_get_ok.set(cr.metrics.shard_get_ok.load(.monotonic));
                ctx.registry.cluster_shard_get_err.set(cr.metrics.shard_get_err.load(.monotonic));
                ctx.registry.cluster_meta_put_ok.set(cr.metrics.meta_put_ok.load(.monotonic));
                ctx.registry.cluster_meta_put_err.set(cr.metrics.meta_put_err.load(.monotonic));
                ctx.registry.cluster_meta_get_ok.set(cr.metrics.meta_get_ok.load(.monotonic));
                ctx.registry.cluster_meta_get_err.set(cr.metrics.meta_get_err.load(.monotonic));
                ctx.registry.cluster_bucket_op_ok.set(cr.metrics.bucket_op_ok.load(.monotonic));
                ctx.registry.cluster_bucket_op_err.set(cr.metrics.bucket_op_err.load(.monotonic));
            }
            const body = ctx.registry.render(request.arena.allocator()) catch {
                http.writeError(out, 500, "Internal Server Error", "");
                out.flush() catch return;
                continue;
            };
            const resp: http.Response = .{
                .status = 200,
                .status_text = "OK",
                .content_type = "text/plain; version=0.0.4",
                .body = .{ .bytes = body },
            };
            writeAndLog(out, &request, &resp, request_id, start_ns, ctx);
            continue;
        }

        var response = router.route(&request, handler_ctx);

        // Add request id header.
        const rid_hdr = std.fmt.allocPrint(request.arena.allocator(), "x-amz-request-id: {s}", .{request_id}) catch "";
        if (request.arena.allocator().alloc([]const u8, response.extra_headers.len + 1)) |combined| {
            for (response.extra_headers, 0..) |h, i| combined[i] = h;
            combined[response.extra_headers.len] = rid_hdr;
            response.extra_headers = combined;
        } else |_| {}

        writeAndLog(out, &request, &response, request_id, start_ns, ctx);

        // Close any owned file in the response body.
        switch (response.body) {
            .file => |fs| if (fs.owns_file) fs.file.close(),
            .encrypted_file => |ef| if (ef.owns_file) ef.file.close(),
            else => {},
        }

        // Drain unread body for keep-alive.
        drainBody(&request) catch return;
    }
}

fn writeAndLog(
    w: *Io.Writer,
    req: *const http.Request,
    resp: *const http.Response,
    rid: []const u8,
    start_ns: i128,
    ctx: Context,
) void {
    const head_only = req.method == .HEAD;
    http.writeResponse(w, resp, head_only) catch return;
    w.flush() catch return;

    const elapsed_ns = std.time.nanoTimestamp() - start_ns;
    const elapsed_ms: u64 = @intCast(@max(0, @divTrunc(elapsed_ns, 1_000_000)));

    ctx.registry.requests_total.inc();
    ctx.registry.bytes_out.add(resp.body.length());
    ctx.registry.bytes_in.add(req.content_length);
    ctx.registry.request_latency_ms.observeMs(elapsed_ms);
    if (resp.status >= 500) ctx.registry.errors_total.inc();

    std.log.info(
        "{{\"rid\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"status\":{d},\"bytes\":{d},\"ms\":{d}}}",
        .{ rid, req.method.name(), req.path, resp.status, resp.body.length(), elapsed_ms },
    );
}

fn handleParseError(w: *Io.Writer, err: anyerror) void {
    const status: u16 = switch (err) {
        error.UnsupportedMethod => 405,
        error.HeaderTooLarge, error.TooManyHeaders => 431,
        error.MalformedRequest => 400,
        else => return,
    };
    const text = switch (status) {
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        else => "Bad Request",
    };
    http.writeError(w, status, text, "");
    w.flush() catch {};
}

fn writeAuthError(w: *Io.Writer, request_id: []const u8) void {
    const xml = @import("xml.zig");
    var fba_buf: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const body = xml.buildError(fba.allocator(), "AccessDenied", "Signature does not match.", "/", request_id) catch "";
    http.writeError(w, 403, "Forbidden", body);
}

/// Paths that bypass IAM policy enforcement: health/metrics probes and the
/// cluster internal endpoint's public health mirror. These are either
/// already handled earlier in `handleConnection` (cluster internal, web
/// console) or need to stay reachable for orchestration tooling regardless
/// of policy state.
fn isExemptPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/healthz") or
        std.mem.eql(u8, path, "/health") or
        std.mem.eql(u8, path, "/readyz") or
        std.mem.eql(u8, path, "/metrics") or
        std.mem.eql(u8, path, "/cluster/health") or
        std.mem.eql(u8, path, "/_simpaniz/cluster/health");
}

fn writeAccessDenied(w: *Io.Writer, request_id: []const u8) void {
    const xml = @import("xml.zig");
    var fba_buf: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const body = xml.buildError(fba.allocator(), "AccessDenied", "Access Denied.", "/", request_id) catch "";
    http.writeError(w, 403, "Forbidden", body);
}

fn drainBody(req: *http.Request) !void {
    const remaining = req.content_length - req.body_consumed;
    if (remaining == 0) return;
    var buf: [16 * 1024]u8 = undefined;
    var left = remaining;
    while (left > 0) {
        const want = @min(left, buf.len);
        const got = req.body_reader.readSliceShort(buf[0..want]) catch return;
        if (got == 0) return;
        left -= got;
    }
}

fn verifyRequestAuth(req: *const http.Request, config: *const Config, iam_store: *const iam.Store) !?iam.Principal {
    const auth_hdr = req.header("authorization") orelse return null;
    if (!std.mem.startsWith(u8, auth_hdr, "AWS4-HMAC-SHA256 ")) return null;

    const date = req.header("x-amz-date") orelse return null;
    const sha = req.header("x-amz-content-sha256") orelse "UNSIGNED-PAYLOAD";
    const host = req.header("host") orelse "";

    var arena = std.heap.ArenaAllocator.init(config.arena.child_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = auth.parseAuthorization(auth_hdr) catch return null;

    // Resolve which credentials to verify against: root config keys, or a
    // matching IAM user's keys. Unknown access keys fail closed.
    var creds: auth.Credentials = undefined;
    var principal: iam.Principal = undefined;
    if (std.mem.eql(u8, parsed.access_key, config.access_key)) {
        creds = .{ .access_key = config.access_key, .secret_key = config.secret_key, .region = config.region };
        principal = .{ .access_key = config.access_key, .is_root = true };
    } else if (iam_store.findUser(parsed.access_key)) |user| {
        creds = .{ .access_key = user.access_key, .secret_key = user.secret_key, .region = config.region };
        principal = .{ .access_key = user.access_key, .is_root = false };
    } else {
        return null;
    }

    var hdr_list = std.ArrayList(auth.Header){};
    var iter = std.mem.splitScalar(u8, parsed.signed_headers, ';');
    while (iter.next()) |name| {
        if (std.mem.eql(u8, name, "host")) {
            hdr_list.append(a, .{ .name = "host", .value = host }) catch return null;
            continue;
        }
        const value = req.header(name) orelse return null;
        hdr_list.append(a, .{ .name = name, .value = value }) catch return null;
    }

    const canonical_query = canonicalizeQuery(a, req.query) catch return null;

    auth.verifyHeaderSignedRequest(a, creds, .{
        .method = req.method.name(),
        .canonical_uri = req.raw_path,
        .canonical_query = canonical_query,
        .headers = hdr_list.items,
        .payload_hash = sha,
        .authorization = auth_hdr,
        .amz_date = date,
    }) catch return null;
    return principal;
}

fn canonicalizeQuery(allocator: Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0) return allocator.dupe(u8, "");
    const Pair = struct { k: []u8, v: []u8 };
    var pairs = std.ArrayList(Pair){};
    defer pairs.deinit(allocator);

    var iter = std.mem.splitScalar(u8, raw, '&');
    while (iter.next()) |p| {
        if (p.len == 0) continue;
        var k_raw: []const u8 = p;
        var v_raw: []const u8 = "";
        if (std.mem.indexOfScalar(u8, p, '=')) |eq| {
            k_raw = p[0..eq];
            v_raw = p[eq + 1 ..];
        }
        const k_dec = try util.urlDecode(allocator, k_raw);
        defer allocator.free(k_dec);
        const v_dec = try util.urlDecode(allocator, v_raw);
        defer allocator.free(v_dec);
        const k_enc = try util.awsUriEncode(allocator, k_dec, true);
        const v_enc = try util.awsUriEncode(allocator, v_dec, true);
        try pairs.append(allocator, .{ .k = k_enc, .v = v_enc });
    }
    std.mem.sort(Pair, pairs.items, {}, struct {
        fn lt(_: void, x: Pair, y: Pair) bool {
            return std.mem.lessThan(u8, x.k, y.k);
        }
    }.lt);
    var out = std.ArrayList(u8){};
    for (pairs.items, 0..) |p, i| {
        if (i > 0) try out.append(allocator, '&');
        try out.appendSlice(allocator, p.k);
        try out.append(allocator, '=');
        try out.appendSlice(allocator, p.v);
        allocator.free(p.k);
        allocator.free(p.v);
    }
    return out.toOwnedSlice(allocator);
}
