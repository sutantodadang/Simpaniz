//! Background self-healing daemon.
//!
//! Walks every (bucket, key) for which this node has a local meta file,
//! reads the meta, then asks the orchestrator to heal any missing shard.

const std = @import("std");
const Allocator = std.mem.Allocator;
const disk = @import("disk_store.zig");
const runtime_mod = @import("runtime.zig");

pub const Stats = struct {
    repaired_total: std.atomic.Value(u64) = .{ .raw = 0 },
    runs_total: std.atomic.Value(u64) = .{ .raw = 0 },
    last_errors: std.atomic.Value(u64) = .{ .raw = 0 },
};

pub fn runOnce(rt: *runtime_mod.ClusterRuntime, allocator: Allocator, stats: *Stats) !void {
    _ = stats.runs_total.fetchAdd(1, .monotonic);
    var ctx: WalkCtx = .{ .rt = rt, .allocator = allocator, .stats = stats };
    try disk.forEachLocalKey(rt.data_dir, allocator, &ctx, visit);
}

const WalkCtx = struct {
    rt: *runtime_mod.ClusterRuntime,
    allocator: Allocator,
    stats: *Stats,
};

fn visit(raw: *anyopaque, bucket: []const u8, key: []const u8) anyerror!void {
    const ctx: *WalkCtx = @ptrCast(@alignCast(raw));
    const meta_opt = ctx.rt.readMeta(bucket, key, ctx.allocator) catch {
        _ = ctx.stats.last_errors.fetchAdd(1, .monotonic);
        return;
    };
    const meta = meta_opt orelse return;
    defer ctx.allocator.free(meta.content_type);
    const repaired = ctx.rt.orchestrator.heal(bucket, key, meta.shard_size) catch {
        _ = ctx.stats.last_errors.fetchAdd(1, .monotonic);
        return;
    };
    if (repaired > 0) _ = ctx.stats.repaired_total.fetchAdd(repaired, .monotonic);
}
