//! `simpaniz admin` — the CLI half of the admin REST API (`admin.zig`).
//! MinIO needs a separate `mc` binary talking to its own admin API;
//! simpaniz ships server + admin client in one binary. This module is a
//! thin SigV4-signed HTTP client (via `s3_client.zig`) against
//! `/_admin/*`, dispatched from `main.zig` before the server starts (see
//! `main.zig`'s `args[1] == "admin"` check) — running `simpaniz admin ...`
//! never binds a listening socket.
const std = @import("std");
const Allocator = std.mem.Allocator;
const s3_client = @import("s3_client.zig");

pub const Plan = struct {
    method: std.http.Method,
    path: []const u8,
    body: ?[]const u8 = null,
};

pub const PlanError = error{ UnknownCommand, MissingArgument, InvalidPolicyJson };

/// Pure mapping from CLI args (post "admin", e.g. `["user","add","ak","sk"]`)
/// to an HTTP plan. No filesystem or network access here — `run` resolves
/// any `--policy <file>` (for `user add`) or positional `<file>` (for
/// `policy set`) argument to bytes *before* calling this, passing them in
/// as `policy_file_content`, so this function stays a pure/testable
/// args -> plan mapping.
pub fn planFromArgs(allocator: Allocator, args: []const []const u8, policy_file_content: ?[]const u8) (PlanError || Allocator.Error)!Plan {
    if (args.len == 0) return error.UnknownCommand;
    const cmd = args[0];

    if (std.mem.eql(u8, cmd, "info")) return .{ .method = .GET, .path = "/_admin/info" };
    if (std.mem.eql(u8, cmd, "config")) return .{ .method = .GET, .path = "/_admin/config" };
    if (std.mem.eql(u8, cmd, "cluster")) {
        if (args.len >= 2 and std.mem.eql(u8, args[1], "decommission")) {
            if (args.len < 3) return error.MissingArgument;
            const path = try std.fmt.allocPrint(allocator, "/_admin/cluster/decommission?node={s}", .{args[2]});
            return .{ .method = .POST, .path = path };
        }
        return .{ .method = .GET, .path = "/_admin/cluster" };
    }

    if (std.mem.eql(u8, cmd, "user")) {
        if (args.len < 2) return error.MissingArgument;
        const sub = args[1];
        if (std.mem.eql(u8, sub, "list")) return .{ .method = .GET, .path = "/_admin/users" };
        if (std.mem.eql(u8, sub, "add")) return planUserAdd(allocator, args, policy_file_content);
        if (std.mem.eql(u8, sub, "rm")) {
            if (args.len < 3) return error.MissingArgument;
            const path = try std.fmt.allocPrint(allocator, "/_admin/users/{s}", .{args[2]});
            return .{ .method = .DELETE, .path = path };
        }
        return error.UnknownCommand;
    }

    if (std.mem.eql(u8, cmd, "policy")) {
        if (args.len < 2) return error.MissingArgument;
        const sub = args[1];
        if (std.mem.eql(u8, sub, "get")) {
            if (args.len < 3) return error.MissingArgument;
            const path = try std.fmt.allocPrint(allocator, "/_admin/policies/{s}", .{args[2]});
            return .{ .method = .GET, .path = path };
        }
        if (std.mem.eql(u8, sub, "set")) {
            if (args.len < 4) return error.MissingArgument;
            const path = try std.fmt.allocPrint(allocator, "/_admin/policies/{s}", .{args[2]});
            return .{ .method = .PUT, .path = path, .body = policy_file_content orelse return error.MissingArgument };
        }
        return error.UnknownCommand;
    }

    return error.UnknownCommand;
}

fn planUserAdd(allocator: Allocator, args: []const []const u8, policy_file_content: ?[]const u8) (PlanError || Allocator.Error)!Plan {
    // user add <access_key> <secret_key> [--policy <file>] [--disabled]
    if (args.len < 4) return error.MissingArgument;
    const path = try std.fmt.allocPrint(allocator, "/_admin/users/{s}", .{args[2]});

    var disabled = false;
    for (args[4..]) |a| {
        if (std.mem.eql(u8, a, "--disabled")) disabled = true;
    }

    var policy_value: ?std.json.Value = null;
    if (policy_file_content) |pj| {
        policy_value = std.json.parseFromSliceLeaky(std.json.Value, allocator, pj, .{}) catch return error.InvalidPolicyJson;
    }

    const Body = struct {
        secret_key: []const u8,
        enabled: bool,
        policy: ?std.json.Value = null,
    };
    const body = std.json.Stringify.valueAlloc(allocator, Body{
        .secret_key = args[3],
        .enabled = !disabled,
        .policy = policy_value,
    }, .{}) catch return error.OutOfMemory;

    return .{ .method = .PUT, .path = path, .body = body };
}

/// If `args` names a command that takes a policy file argument, return its
/// path (for `run` to read before calling `planFromArgs`).
fn policyFileArgFor(args: []const []const u8) ?[]const u8 {
    if (args.len >= 2 and std.mem.eql(u8, args[0], "user") and std.mem.eql(u8, args[1], "add")) {
        var i: usize = 4;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--policy") and i + 1 < args.len) return args[i + 1];
        }
        return null;
    }
    if (args.len >= 4 and std.mem.eql(u8, args[0], "policy") and std.mem.eql(u8, args[1], "set")) {
        return args[3];
    }
    return null;
}

fn isHelp(s: []const u8) bool {
    return std.mem.eql(u8, s, "help") or std.mem.eql(u8, s, "--help") or std.mem.eql(u8, s, "-h");
}

fn getEnvDefault(a: Allocator, key: []const u8, default: []const u8) []const u8 {
    return std.process.getEnvVarOwned(a, key) catch a.dupe(u8, default) catch default;
}

/// Entry point for `simpaniz admin <args...>` (args already has "admin"
/// stripped). Never returns an error to the caller — failures print to
/// stderr and exit(1)/exit(2) directly, matching a typical CLI's contract.
pub fn run(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0 or isHelp(args[0])) {
        printUsage();
        return;
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var policy_file_content: ?[]const u8 = null;
    if (policyFileArgFor(args)) |file_path| {
        policy_file_content = std.fs.cwd().readFileAlloc(a, file_path, 1024 * 1024) catch |e| {
            std.debug.print("simpaniz admin: failed to read {s}: {s}\n", .{ file_path, @errorName(e) });
            std.process.exit(1);
        };
    }

    const plan = planFromArgs(a, args, policy_file_content) catch |e| {
        std.debug.print("simpaniz admin: {s}\n\n", .{@errorName(e)});
        printUsage();
        std.process.exit(2);
    };

    const endpoint = getEnvDefault(a, "SIMPANIZ_ADMIN_ENDPOINT", "http://127.0.0.1:9000");
    const access_key = getEnvDefault(a, "SIMPANIZ_ACCESS_KEY", "");
    const secret_key = getEnvDefault(a, "SIMPANIZ_SECRET_KEY", "");
    const region = getEnvDefault(a, "SIMPANIZ_REGION", "us-east-1");
    if (access_key.len == 0 or secret_key.len == 0) {
        std.debug.print("simpaniz admin: set SIMPANIZ_ACCESS_KEY and SIMPANIZ_SECRET_KEY (see the server's <data_dir>/.simpaniz-credentials on first run).\n", .{});
        std.process.exit(1);
    }

    const creds = s3_client.Credentials{ .access_key = access_key, .secret_key = secret_key, .region = region };
    const resp = s3_client.request(a, creds, endpoint, plan.method, plan.path, plan.body) catch |e| {
        std.debug.print("simpaniz admin: request failed: {s}\n", .{@errorName(e)});
        // ponytail: self-signed TLS certs aren't verified by this client
        // yet (std.http.Client's default CA bundle won't trust them).
        // No --insecure flag today; point the operator at the workaround.
        if (std.mem.startsWith(u8, endpoint, "https://")) {
            std.debug.print("hint: set SIMPANIZ_ADMIN_ENDPOINT to http:// or use a CA-signed cert; --insecure is not supported yet.\n", .{});
        }
        std.process.exit(1);
    };

    if (resp.status >= 200 and resp.status < 300) {
        std.fs.File.stdout().writeAll(resp.body) catch {};
        std.fs.File.stdout().writeAll("\n") catch {};
    } else {
        std.debug.print("simpaniz admin: HTTP {d}\n", .{resp.status});
        std.fs.File.stderr().writeAll(resp.body) catch {};
        std.fs.File.stderr().writeAll("\n") catch {};
        std.process.exit(1);
    }
}

fn printUsage() void {
    const usage =
        \\simpaniz admin — manage a running simpaniz server. No separate client binary needed.
        \\
        \\Usage:
        \\  simpaniz admin info
        \\  simpaniz admin user list
        \\  simpaniz admin user add <access_key> <secret_key> [--policy <file>] [--disabled]
        \\  simpaniz admin user rm <access_key>
        \\  simpaniz admin policy get <name>
        \\  simpaniz admin policy set <name> <file>
        \\  simpaniz admin cluster
        \\  simpaniz admin cluster decommission <node-id>
        \\  simpaniz admin config
        \\  simpaniz admin help
        \\
        \\Environment:
        \\  SIMPANIZ_ADMIN_ENDPOINT   default http://127.0.0.1:9000
        \\  SIMPANIZ_ACCESS_KEY       required
        \\  SIMPANIZ_SECRET_KEY       required
        \\  SIMPANIZ_REGION           default us-east-1
        \\
    ;
    std.fs.File.stdout().writeAll(usage) catch {};
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "planFromArgs: info maps to GET /_admin/info" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const plan = try planFromArgs(arena.allocator(), &.{"info"}, null);
    try std.testing.expectEqual(std.http.Method.GET, plan.method);
    try std.testing.expectEqualStrings("/_admin/info", plan.path);
    try std.testing.expect(plan.body == null);
}

test "planFromArgs: user add maps to PUT with JSON body" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const plan = try planFromArgs(arena.allocator(), &.{ "user", "add", "AKIAUSER1", "a-secret-key" }, null);
    try std.testing.expectEqual(std.http.Method.PUT, plan.method);
    try std.testing.expectEqualStrings("/_admin/users/AKIAUSER1", plan.path);
    const body = plan.body orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, body, "\"secret_key\":\"a-secret-key\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enabled\":true") != null);
}

test "planFromArgs: user add --disabled sets enabled false" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const plan = try planFromArgs(arena.allocator(), &.{ "user", "add", "AKIAUSER1", "a-secret-key", "--disabled" }, null);
    const body = plan.body orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, body, "\"enabled\":false") != null);
}

test "planFromArgs: user rm maps to DELETE" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const plan = try planFromArgs(arena.allocator(), &.{ "user", "rm", "AKIAUSER1" }, null);
    try std.testing.expectEqual(std.http.Method.DELETE, plan.method);
    try std.testing.expectEqualStrings("/_admin/users/AKIAUSER1", plan.path);
}

test "planFromArgs: policy get/set map correctly" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const get_plan = try planFromArgs(arena.allocator(), &.{ "policy", "get", "readonly" }, null);
    try std.testing.expectEqual(std.http.Method.GET, get_plan.method);
    try std.testing.expectEqualStrings("/_admin/policies/readonly", get_plan.path);

    const set_plan = try planFromArgs(arena.allocator(), &.{ "policy", "set", "readonly", "p.json" }, "{\"Statement\":[]}");
    try std.testing.expectEqual(std.http.Method.PUT, set_plan.method);
    try std.testing.expectEqualStrings("/_admin/policies/readonly", set_plan.path);
    try std.testing.expectEqualStrings("{\"Statement\":[]}", set_plan.body.?);
}

test "planFromArgs: cluster and config map to GET" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const cluster_plan = try planFromArgs(arena.allocator(), &.{"cluster"}, null);
    try std.testing.expectEqualStrings("/_admin/cluster", cluster_plan.path);
    const config_plan = try planFromArgs(arena.allocator(), &.{"config"}, null);
    try std.testing.expectEqualStrings("/_admin/config", config_plan.path);
}

test "planFromArgs: cluster decommission maps to POST with node query param" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const plan = try planFromArgs(arena.allocator(), &.{ "cluster", "decommission", "n1" }, null);
    try std.testing.expectEqual(std.http.Method.POST, plan.method);
    try std.testing.expectEqualStrings("/_admin/cluster/decommission?node=n1", plan.path);

    try std.testing.expectError(error.MissingArgument, planFromArgs(arena.allocator(), &.{ "cluster", "decommission" }, null));
}

test "planFromArgs: unknown command errors" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectError(error.UnknownCommand, planFromArgs(arena.allocator(), &.{"bogus"}, null));
    try std.testing.expectError(error.UnknownCommand, planFromArgs(arena.allocator(), &.{}, null));
}

test "planFromArgs: missing required args errors" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectError(error.MissingArgument, planFromArgs(arena.allocator(), &.{ "user", "add", "onlyak" }, null));
    try std.testing.expectError(error.MissingArgument, planFromArgs(arena.allocator(), &.{"user"}, null));
}
