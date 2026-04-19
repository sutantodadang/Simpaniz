//! Simpaniz — S3-compatible object storage server entry point.
const std = @import("std");
const Config = @import("config.zig");
const server = @import("server.zig");
const metrics = @import("metrics.zig");
const bootstrap = @import("bootstrap.zig");

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var config = Config.load(gpa);
    defer config.deinit();

    std.log.info("Simpaniz v0.1.1 starting (data={s}, region={s})", .{ config.data_dir, config.region });

    if (config.tls_cert_path.len > 0 or config.tls_key_path.len > 0) {
        std.log.err(
            \\SIMPANIZ_TLS_CERT/SIMPANIZ_TLS_KEY are set, but in-process TLS is not yet
            \\implemented. Terminate HTTPS at a reverse proxy (nginx, caddy, haproxy)
            \\and forward plaintext HTTP to Simpaniz. See SECURITY.md for an example.
            \\Refusing to start so you do not accidentally serve plaintext.
        , .{});
        return error.TlsNotImplemented;
    }

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

    server.installSignalHandlers();
    try server.start(.{
        .config = &config,
        .data_dir = data_dir,
        .gpa = gpa,
        .registry = &registry,
        .cluster = cluster_rt,
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
}
