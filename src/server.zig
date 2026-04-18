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

const DaemonCtx = struct {
    data_dir: std.fs.Dir,
    gpa: Allocator,
    registry: *metrics.Registry,
    interval_ns: u64,
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
        const stats = storage.sweepLifecycle(c.data_dir, c.gpa, now) catch |e| {
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
            dc.* = .{ .data_dir = ctx.data_dir, .gpa = ctx.gpa, .registry = ctx.registry, .interval_ns = ctx.config.lifecycle_interval_s * std.time.ns_per_s };
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

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(&read_buf);
    var sw = stream.writer(&write_buf);

    while (!shutdown_requested.load(.seq_cst)) {
        const start_ns = std.time.nanoTimestamp();
        _ = ctx.registry.requests_in_flight.fetchAdd(1, .monotonic);
        defer _ = ctx.registry.requests_in_flight.fetchSub(1, .monotonic);

        var request = http.parseRequest(sr.interface(), ctx.gpa, .{
            .max_header_bytes = ctx.config.max_header_bytes,
            .max_headers = ctx.config.max_headers,
        }) catch |err| {
            // Quietly close on EOF / closed-connection (common with curl one-shot).
            if (err == error.ReadFailed) return;
            handleParseError(&sw.interface, err);
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
            http.writeError(&sw.interface, 413, "Payload Too Large", "");
            sw.interface.flush() catch return;
            return;
        }

        // Cluster internal endpoint — bypass SigV4, authenticated via shared
        // secret in X-Simpaniz-Cluster-Auth header.
        if (ctx.cluster != null and cluster.isInternalPath(request.path)) {
            const cr = ctx.cluster.?;
            const resp = cluster.internalHandler(&request, ctx.data_dir, cr.config.cluster_secret, ctx.config.max_body_bytes);
            writeAndLog(&sw.interface, &request, &resp, request_id, start_ns, ctx);
            drainBody(&request) catch return;
            continue;
        }

        // Auth (best-effort SigV4 verification when configured).
        if (ctx.config.auth_required) {
            const ok = verifyRequestAuth(&request, ctx.config) catch false;
            if (!ok) {
                ctx.registry.auth_failures.inc();
                writeAuthError(&sw.interface, request_id);
                sw.interface.flush() catch return;
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
                http.writeError(&sw.interface, 500, "Internal Server Error", "");
                sw.interface.flush() catch return;
                continue;
            };
            const resp: http.Response = .{
                .status = 200,
                .status_text = "OK",
                .content_type = "text/plain; version=0.0.4",
                .body = .{ .bytes = body },
            };
            writeAndLog(&sw.interface, &request, &resp, request_id, start_ns, ctx);
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

        writeAndLog(&sw.interface, &request, &response, request_id, start_ns, ctx);

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

fn verifyRequestAuth(req: *const http.Request, config: *const Config) !bool {
    const auth_hdr = req.header("authorization") orelse return false;
    if (!std.mem.startsWith(u8, auth_hdr, "AWS4-HMAC-SHA256 ")) return false;

    const date = req.header("x-amz-date") orelse return false;
    const sha = req.header("x-amz-content-sha256") orelse "UNSIGNED-PAYLOAD";
    const host = req.header("host") orelse "";

    var arena = std.heap.ArenaAllocator.init(config.arena.child_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = auth.parseAuthorization(auth_hdr) catch return false;

    var hdr_list = std.ArrayList(auth.Header){};
    var iter = std.mem.splitScalar(u8, parsed.signed_headers, ';');
    while (iter.next()) |name| {
        if (std.mem.eql(u8, name, "host")) {
            hdr_list.append(a, .{ .name = "host", .value = host }) catch return false;
            continue;
        }
        const value = req.header(name) orelse return false;
        hdr_list.append(a, .{ .name = name, .value = value }) catch return false;
    }

    const canonical_query = canonicalizeQuery(a, req.query) catch return false;

    auth.verifyHeaderSignedRequest(a, .{
        .access_key = config.access_key,
        .secret_key = config.secret_key,
        .region = config.region,
    }, .{
        .method = req.method.name(),
        .canonical_uri = req.raw_path,
        .canonical_query = canonical_query,
        .headers = hdr_list.items,
        .payload_hash = sha,
        .authorization = auth_hdr,
        .amz_date = date,
    }) catch return false;
    return true;
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
