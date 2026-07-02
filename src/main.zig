//! Simpaniz — S3-compatible object storage server entry point.
const std = @import("std");
const Config = @import("config.zig");
const server = @import("server.zig");
const metrics = @import("metrics.zig");
const bootstrap = @import("bootstrap.zig");
const iam = @import("iam.zig");
const events = @import("events.zig");
const tls_server = @import("tls_server.zig");
const index_mod = @import("index.zig");
const tiering_mod = @import("tiering.zig");
const sts = @import("sts.zig");
const admin_cli = @import("admin_cli.zig");
const timeseries = @import("timeseries.zig");

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // `simpaniz admin ...` is a CLI client against a running server's
    // `/_admin/*` REST API (see `admin_cli.zig`) — it never starts a
    // server, so this dispatch happens before any config/data-dir/listener
    // setup below.
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "admin")) {
        return admin_cli.run(gpa, args[2..]);
    }

    var config = Config.load(gpa);
    defer config.deinit();

    std.log.info("Simpaniz v0.1.1 starting (data={s}, region={s})", .{ config.data_dir, config.region });

    var tls_ctx: ?*tls_server.ServerContext = null;
    if (config.tls_cert_path.len > 0 or config.tls_key_path.len > 0) {
        if (config.tls_cert_path.len == 0 or config.tls_key_path.len == 0) {
            std.log.err("Set BOTH SIMPANIZ_TLS_CERT and SIMPANIZ_TLS_KEY (or neither).", .{});
            return error.TlsConfigIncomplete;
        }
        tls_ctx = try tls_server.ServerContext.load(gpa, config.tls_cert_path, config.tls_key_path);
        std.log.info("TLS enabled (in-process TLS 1.3): cert={s}", .{config.tls_cert_path});
    }
    defer if (tls_ctx) |t| t.deinit();

    var data_dir = blk: {
        if (std.fs.path.isAbsolute(config.data_dir)) {
            std.fs.makeDirAbsolute(config.data_dir) catch |e| switch (e) {
                error.PathAlreadyExists => {},
                else => return e,
            };
            break :blk try std.fs.openDirAbsolute(config.data_dir, .{ .iterate = true });
        }
        try std.fs.cwd().makePath(config.data_dir);
        break :blk try std.fs.cwd().openDir(config.data_dir, .{ .iterate = true });
    };
    defer data_dir.close();

    // First-run admin credential bootstrap. Generates and persists a root
    // credential under data_dir on first launch when none is configured via
    // env vars, mirroring the MinIO root-user UX so the web console works
    // out of the box.
    try bootstrap.ensureCredentials(&config, data_dir);

    var iam_store = iam.load(gpa, data_dir);
    defer iam_store.deinit();
    std.log.info("IAM: {d} user(s) loaded", .{iam_store.users.len});

    var sts_store = sts.StsStore.init(gpa);
    defer sts_store.deinit();

    var oidc_config = sts.OidcConfig.load(gpa, data_dir);
    defer oidc_config.deinit();
    std.log.info("STS enabled; OIDC: {s}", .{if (oidc_config.enabled) "on" else "off"});

    var registry = metrics.Registry{ .started_unix = std.time.timestamp() };

    // Cluster runtime — only built when SIMPANIZ_NODE_ID is set.
    const cluster = @import("cluster.zig");
    var cluster_cfg = try cluster.loadConfig(gpa);
    defer cluster_cfg.deinit();

    var cluster_rt: ?*cluster.ClusterRuntime = null;
    if (cluster_cfg.enabled) {
        cluster_rt = try cluster.ClusterRuntime.init(gpa, &cluster_cfg, data_dir);
        const repl_auth = std.process.getEnvVarOwned(gpa, "SIMPANIZ_REPL_AUTH") catch null;
        defer if (repl_auth) |a| gpa.free(a);
        cluster_rt.?.startReplication(repl_auth) catch |e| {
            std.log.warn("ssr disabled: {any}", .{e});
        };
        std.log.info(
            "cluster mode enabled: node={s} self_index={d} peers={d} k={d} m={d} repl_targets={d}",
            .{ cluster_cfg.node_id, cluster_cfg.self_index, cluster_cfg.peers.len, cluster_cfg.ec_k, cluster_cfg.ec_m, cluster_cfg.repl_targets_raw.len },
        );
    }
    defer if (cluster_rt) |rt| rt.deinit();

    // Event notifications — only wired up when a webhook target is configured.
    const notify_url = std.process.getEnvVarOwned(gpa, "SIMPANIZ_NOTIFY_WEBHOOK") catch null;
    defer if (notify_url) |u| gpa.free(u);
    var notifier: ?*events.Notifier = null;
    if (notify_url) |u| {
        notifier = try events.Notifier.init(gpa, u, config.region, data_dir);
        try notifier.?.start();
        std.log.info("event notifications enabled: webhook={s}", .{u});
    }
    defer if (notifier) |n| n.deinit();

    // Persistent object-listing index — single-node only (cluster mode keeps
    // using the FS-walk listing since shards aren't locally enumerable).
    var index_mgr = index_mod.Manager.init(gpa, data_dir);
    defer index_mgr.deinit();

    // Cold-storage tiering target for lifecycle Transition rules — off
    // unless SIMPANIZ_TIER_DIR or SIMPANIZ_TIER_URL is set.
    var tiering_ctx = tiering_mod.Tiering.init(gpa);
    switch (tiering_ctx.mode) {
        .off => {},
        .local => std.log.info("tiering enabled: mode=local", .{}),
        .remote => std.log.info("tiering enabled: mode=remote url={s} bucket={s}", .{ tiering_ctx.url, tiering_ctx.tier_bucket }),
    }

    // In-process metric history for the console's Metrics dashboard — an
    // in-memory ring, no Prometheus/Grafana required. Disabled entirely
    // when SIMPANIZ_METRICS_SAMPLE_S=0 (dashboard API still answers:
    // /summary from live registry counters, /series with an empty list).
    const metrics_sample_s = timeseries.readSampleIntervalEnv(gpa);
    var tseries_store: ?*timeseries.Store = null;
    if (metrics_sample_s > 0) {
        tseries_store = try timeseries.Store.init(gpa, &registry, timeseries.default_capacity, metrics_sample_s);
        try tseries_store.?.start();
        std.log.info("metrics dashboard: sampling every {d}s (24h ring)", .{metrics_sample_s});
    } else {
        std.log.info("metrics dashboard: sampler disabled (SIMPANIZ_METRICS_SAMPLE_S=0)", .{});
    }
    defer if (tseries_store) |ts| ts.deinit();

    server.installSignalHandlers();
    try server.start(.{
        .config = &config,
        .data_dir = data_dir,
        .gpa = gpa,
        .registry = &registry,
        .cluster = cluster_rt,
        .iam = &iam_store,
        .notifier = notifier,
        .tls = tls_ctx,
        .index = if (cluster_rt == null) &index_mgr else null,
        .tiering = &tiering_ctx,
        .sts = &sts_store,
        .oidc = &oidc_config,
        .tseries = tseries_store,
    });
}

test {
    // Pull tests from all modules.
    _ = @import("util.zig");
    _ = @import("auth.zig");
    _ = @import("xml.zig");
    _ = @import("http.zig");
    _ = @import("storage.zig");
    _ = @import("metrics.zig");
    _ = @import("handlers.zig");
    _ = @import("router.zig");
    _ = @import("cluster.zig");
    _ = @import("iam.zig");
    _ = @import("events.zig");
    _ = @import("tls_server.zig");
    _ = @import("index.zig");
    _ = @import("tiering.zig");
    _ = @import("sts.zig");
    _ = @import("admin.zig");
    _ = @import("admin_cli.zig");
    _ = @import("s3_client.zig");
    _ = @import("timeseries.zig");
    _ = @import("dashboard.zig");
}
