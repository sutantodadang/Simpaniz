//! Admin REST API (`/_admin/*`) — the transport the `simpaniz admin` CLI
//! subcommand (see `admin_cli.zig`) talks to. This is the differentiator
//! vs. MinIO, which needs a separate `mc` binary + its own auth dance:
//! simpaniz ships server + admin client in one binary, and the admin API
//! reuses the same SigV4 auth the S3 API already has.
//!
//! Every route is root-only — this is process administration (IAM user/
//! policy management, config visibility), not S3 data plane. In anonymous
//! mode (auth disabled server-wide) the API is disabled entirely: there is
//! no non-root principal to distinguish from root, so "root-only" can't be
//! enforced and the safe default is to refuse instead of silently trusting
//! every caller.
//!
//! ponytail: minimal REST surface — one resource at a time, no pagination,
//! no bulk ops. Matches exactly what `admin_cli.zig` needs today.
const std = @import("std");
const http = @import("http.zig");
const xml = @import("xml.zig");
const handlers = @import("handlers.zig");
const HandlerContext = handlers.HandlerContext;

const MAX_BODY_BYTES = 256 * 1024;
const POLICIES_DIR = ".simpaniz-iam/policies";

pub fn handle(ctx: HandlerContext, req: *http.Request) http.Response {
    const principal = ctx.principal orelse return accessDenied(ctx, "Admin API requires authentication.");
    if (!principal.is_root) return accessDenied(ctx, "Admin API is root-only.");

    const path = req.path;
    if (std.mem.eql(u8, path, "/_admin/info")) return info(ctx, req);
    if (std.mem.eql(u8, path, "/_admin/users")) return usersList(ctx, req);
    if (std.mem.startsWith(u8, path, "/_admin/users/")) {
        return userItem(ctx, req, path["/_admin/users/".len..]);
    }
    if (std.mem.startsWith(u8, path, "/_admin/policies/")) {
        return policyItem(ctx, req, path["/_admin/policies/".len..]);
    }
    if (std.mem.eql(u8, path, "/_admin/cluster")) return clusterInfo(ctx, req);
    if (std.mem.eql(u8, path, "/_admin/config")) return configInfo(ctx, req);

    return jsonErr(ctx, 404, "Not Found", "NotFound", "No such admin endpoint.");
}

// ── /_admin/info ─────────────────────────────────────────────────────────────

fn info(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);
    const Resp = struct {
        version: []const u8,
        uptime_s: i64,
        mode: []const u8,
        tls: bool,
        iam_users: usize,
        sse_configured: bool,
    };
    const now = std.time.timestamp();
    const resp = Resp{
        .version = "0.1.1",
        .uptime_s = if (ctx.started_unix > 0) @max(0, now - ctx.started_unix) else 0,
        .mode = if (ctx.cluster != null) "cluster" else "single",
        .tls = if (ctx.config) |c| c.tls_cert_path.len > 0 else false,
        .iam_users = if (ctx.iam) |store| store.users.len else 0,
        .sse_configured = ctx.master_key != null,
    };
    return jsonOk(ctx, resp);
}

// ── /_admin/users, /_admin/users/<access_key> ───────────────────────────────

fn usersList(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);
    const store = ctx.iam orelse return internalErr(ctx);
    const body = store.listUsersJson(ctx.allocator) catch return internalErr(ctx);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

fn userItem(ctx: HandlerContext, req: *http.Request, access_key: []const u8) http.Response {
    if (access_key.len == 0) return jsonErr(ctx, 404, "Not Found", "NotFound", "Missing access key.");
    return switch (req.method) {
        .PUT => putUser(ctx, req, access_key),
        .DELETE => deleteUser(ctx, access_key),
        else => methodNotAllowed(ctx),
    };
}

fn putUser(ctx: HandlerContext, req: *http.Request, access_key: []const u8) http.Response {
    if (!validAccessKey(access_key)) {
        return jsonErr(ctx, 400, "Bad Request", "InvalidArgument", "access_key must be 3-64 alphanumeric/dash characters.");
    }
    const store = ctx.iam orelse return internalErr(ctx);

    const body = req.readBodyAlloc(ctx.allocator, MAX_BODY_BYTES) catch {
        return jsonErr(ctx, 400, "Bad Request", "InvalidRequest", "Failed to read body (too large or malformed).");
    };

    const doc = std.json.parseFromSliceLeaky(std.json.Value, ctx.allocator, body, .{}) catch {
        return jsonErr(ctx, 400, "Bad Request", "MalformedJSON", "Body is not valid JSON.");
    };
    if (doc != .object) return jsonErr(ctx, 400, "Bad Request", "MalformedJSON", "Body must be a JSON object.");
    const obj = doc.object;

    const secret_v = obj.get("secret_key") orelse return jsonErr(ctx, 400, "Bad Request", "InvalidArgument", "Missing secret_key.");
    if (secret_v != .string) return jsonErr(ctx, 400, "Bad Request", "InvalidArgument", "secret_key must be a string.");
    const secret_key = secret_v.string;
    if (secret_key.len < 8) return jsonErr(ctx, 400, "Bad Request", "InvalidArgument", "secret_key must be at least 8 characters.");

    var enabled = true;
    if (obj.get("enabled")) |ev| {
        if (ev == .bool) enabled = ev.bool;
    }

    var policy_json: ?[]const u8 = null;
    if (obj.get("policy")) |pv| {
        if (pv != .null) {
            policy_json = std.json.Stringify.valueAlloc(ctx.allocator, pv, .{}) catch return internalErr(ctx);
        }
    }

    store.upsertUser(ctx.data_dir, access_key, secret_key, policy_json, enabled) catch return internalErr(ctx);
    return jsonOk(ctx, .{ .ok = true });
}

fn deleteUser(ctx: HandlerContext, access_key: []const u8) http.Response {
    const store = ctx.iam orelse return internalErr(ctx);
    const removed = store.removeUser(ctx.data_dir, access_key) catch return internalErr(ctx);
    if (!removed) return jsonErr(ctx, 404, "Not Found", "NoSuchUser", "No such user.");
    return .{ .status = 204, .status_text = "No Content" };
}

// ── /_admin/policies/<name> ──────────────────────────────────────────────────

fn policyItem(ctx: HandlerContext, req: *http.Request, name: []const u8) http.Response {
    if (!validPolicyName(name)) {
        return jsonErr(ctx, 400, "Bad Request", "InvalidArgument", "policy name must be 1-64 alphanumeric/dash characters.");
    }
    return switch (req.method) {
        .GET => getPolicy(ctx, name),
        .PUT => putPolicy(ctx, req, name),
        else => methodNotAllowed(ctx),
    };
}

fn getPolicy(ctx: HandlerContext, name: []const u8) http.Response {
    var dir = ctx.data_dir.openDir(POLICIES_DIR, .{}) catch {
        return jsonErr(ctx, 404, "Not Found", "NoSuchPolicy", "No such policy.");
    };
    defer dir.close();
    var name_buf: [80]u8 = undefined;
    const fname = std.fmt.bufPrint(&name_buf, "{s}.json", .{name}) catch return internalErr(ctx);
    const bytes = dir.readFileAlloc(ctx.allocator, fname, MAX_BODY_BYTES) catch {
        return jsonErr(ctx, 404, "Not Found", "NoSuchPolicy", "No such policy.");
    };
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = bytes } };
}

fn putPolicy(ctx: HandlerContext, req: *http.Request, name: []const u8) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, MAX_BODY_BYTES) catch {
        return jsonErr(ctx, 400, "Bad Request", "InvalidRequest", "Failed to read body (too large or malformed).");
    };
    // Validate it parses as JSON; the parsed tree itself isn't needed —
    // the file is stored as raw bytes so bucket-policy evaluation (which
    // re-parses on every request) sees exactly what was PUT.
    _ = std.json.parseFromSliceLeaky(std.json.Value, ctx.allocator, body, .{}) catch {
        return jsonErr(ctx, 400, "Bad Request", "MalformedJSON", "Body is not valid JSON.");
    };

    var dir = ctx.data_dir.makeOpenPath(POLICIES_DIR, .{}) catch return internalErr(ctx);
    defer dir.close();
    var name_buf: [80]u8 = undefined;
    const fname = std.fmt.bufPrint(&name_buf, "{s}.json", .{name}) catch return internalErr(ctx);
    dir.writeFile(.{ .sub_path = fname, .data = body }) catch return internalErr(ctx);
    return jsonOk(ctx, .{ .ok = true });
}

// ── /_admin/cluster ───────────────────────────────────────────────────────────

fn clusterInfo(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);
    const cr = ctx.cluster orelse return jsonOk(ctx, .{ .cluster = false });
    const membership_json = cr.membership.snapshotJson(ctx.allocator) catch "[]";
    const body = std.fmt.allocPrint(
        ctx.allocator,
        "{{\"cluster\":true,\"node_id\":\"{s}\",\"k\":{d},\"m\":{d},\"membership\":{s}}}",
        .{ cr.config.node_id, cr.config.ec_k, cr.config.ec_m, membership_json },
    ) catch return internalErr(ctx);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

// ── /_admin/config ───────────────────────────────────────────────────────────

fn configInfo(ctx: HandlerContext, req: *http.Request) http.Response {
    if (req.method != .GET) return methodNotAllowed(ctx);
    const cfg = ctx.config orelse return internalErr(ctx);
    const tier_mode: []const u8 = if (ctx.tiering) |t| switch (t.mode) {
        .off => "off",
        .local => "local",
        .remote => "remote",
    } else "off";
    const Resp = struct {
        region: []const u8,
        port: u16,
        data_dir: []const u8,
        max_conns: u32,
        tls: bool,
        cluster_enabled: bool,
        notify_webhook_set: bool,
        tier_mode: []const u8,
        master_key_set: bool,
    };
    const resp = Resp{
        .region = cfg.region,
        .port = cfg.port,
        .data_dir = cfg.data_dir,
        .max_conns = cfg.max_conns,
        .tls = cfg.tls_cert_path.len > 0,
        .cluster_enabled = ctx.cluster != null,
        .notify_webhook_set = ctx.notifier != null,
        .tier_mode = tier_mode,
        .master_key_set = ctx.master_key != null,
    };
    return jsonOk(ctx, resp);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Root-check failure — kept as the same S3 AccessDenied XML shape the rest
/// of the server uses (see `server.zig`'s `writeAccessDenied`), since it's
/// the same failure class (auth), just surfaced via a different route.
fn accessDenied(ctx: HandlerContext, message: []const u8) http.Response {
    const body = xml.buildError(ctx.allocator, "AccessDenied", message, "/_admin", ctx.request_id) catch "";
    return .{ .status = 403, .status_text = "Forbidden", .body = .{ .bytes = body } };
}

fn jsonOk(ctx: HandlerContext, value: anytype) http.Response {
    const body = std.json.Stringify.valueAlloc(ctx.allocator, value, .{}) catch "{}";
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
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

fn validAccessKey(s: []const u8) bool {
    if (s.len < 3 or s.len > 64) return false;
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-')) return false;
    }
    return true;
}

fn validPolicyName(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '-')) return false;
    }
    return true;
}

// ── Tests ────────────────────────────────────────────────────────────────────

const iam = @import("iam.zig");

fn testCtx(tmp_dir: std.fs.Dir, iam_store: *iam.Store, principal: ?iam.Principal, allocator: std.mem.Allocator) HandlerContext {
    return .{
        .data_dir = tmp_dir,
        .allocator = allocator,
        .request_id = "test-request",
        .region = "us-east-1",
        .iam = iam_store,
        .principal = principal,
    };
}

test "handle: non-root principal gets 403 AccessDenied" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "AKIAUSER1", .is_root = false }, arena.allocator());

    var fbs = std.Io.Reader.fixed("GET /_admin/info HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 403), resp.status);
}

test "handle: anonymous (no principal) gets 403 AccessDenied" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, null, arena.allocator());

    var fbs = std.Io.Reader.fixed("GET /_admin/info HTTP/1.1\r\nHost: h\r\n\r\n");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();

    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 403), resp.status);
}

test "handle: root gets info and users list" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "root", .is_root = true }, arena.allocator());

    {
        var fbs = std.Io.Reader.fixed("GET /_admin/info HTTP/1.1\r\nHost: h\r\n\r\n");
        var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
        defer req.deinit();
        const resp = handle(ctx, &req);
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"mode\"") != null);
    }
    {
        var fbs = std.Io.Reader.fixed("GET /_admin/users HTTP/1.1\r\nHost: h\r\n\r\n");
        var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
        defer req.deinit();
        const resp = handle(ctx, &req);
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "\"users\"") != null);
    }
}

test "putUser: short secret_key rejected with 400" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "root", .is_root = true }, arena.allocator());

    var fbs = std.Io.Reader.fixed("PUT /_admin/users/AKIAUSER1 HTTP/1.1\r\nHost: h\r\nContent-Length: 20\r\n\r\n{\"secret_key\":\"short\"}");
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();
    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 400), resp.status);
}

test "putUser: invalid access_key characters rejected with 400" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "root", .is_root = true }, arena.allocator());

    const body = "{\"secret_key\":\"a-long-enough-secret\"}";
    var buf: [256]u8 = undefined;
    const req_text = std.fmt.bufPrint(&buf, "PUT /_admin/users/bad!key HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    var fbs = std.Io.Reader.fixed(req_text);
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();
    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 400), resp.status);
}

test "putUser: valid request upserts and is retrievable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "root", .is_root = true }, arena.allocator());

    const body = "{\"secret_key\":\"a-long-enough-secret\"}";
    var buf: [256]u8 = undefined;
    const req_text = std.fmt.bufPrint(&buf, "PUT /_admin/users/AKIAUSER1 HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    var fbs = std.Io.Reader.fixed(req_text);
    var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
    defer req.deinit();
    const resp = handle(ctx, &req);
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(store.findUser("AKIAUSER1") != null);
}

test "policy PUT/GET round-trip; invalid JSON rejected with 400" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = iam.Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ctx = testCtx(tmp.dir, &store, .{ .access_key = "root", .is_root = true }, arena.allocator());

    // Invalid JSON body.
    {
        const body = "not json";
        var buf: [256]u8 = undefined;
        const req_text = std.fmt.bufPrint(&buf, "PUT /_admin/policies/readonly HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
        var fbs = std.Io.Reader.fixed(req_text);
        var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
        defer req.deinit();
        const resp = handle(ctx, &req);
        try std.testing.expectEqual(@as(u16, 400), resp.status);
    }

    // Valid round-trip.
    {
        const body = "{\"Statement\":[]}";
        var buf: [256]u8 = undefined;
        const req_text = std.fmt.bufPrint(&buf, "PUT /_admin/policies/readonly HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
        var fbs = std.Io.Reader.fixed(req_text);
        var req = try http.parseRequest(&fbs, std.testing.allocator, .{});
        defer req.deinit();
        const put_resp = handle(ctx, &req);
        try std.testing.expectEqual(@as(u16, 200), put_resp.status);

        var fbs2 = std.Io.Reader.fixed("GET /_admin/policies/readonly HTTP/1.1\r\nHost: h\r\n\r\n");
        var req2 = try http.parseRequest(&fbs2, std.testing.allocator, .{});
        defer req2.deinit();
        const get_resp = handle(ctx, &req2);
        try std.testing.expectEqual(@as(u16, 200), get_resp.status);
        try std.testing.expect(std.mem.indexOf(u8, get_resp.body.bytes, "Statement") != null);
    }
}
