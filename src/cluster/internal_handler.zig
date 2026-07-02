//! Handler for the internal cluster endpoint at `/_simpaniz/...`.
//! Authenticated via constant-time compare on the
//! `X-Simpaniz-Cluster-Auth` header; this bypasses S3 SigV4.
//!
//! Routes:
//!   PUT|GET|DELETE /_simpaniz/shards/<bucket>/<key>/<idx>
//!   PUT|GET|DELETE /_simpaniz/meta/<bucket>/<key>
//!   GET            /_simpaniz/ping                 membership snapshot (probe + gossip piggyback)
//!   POST           /_simpaniz/join                  {"id","host","port"} -> announce + adopt
//!
//! Stripe-streaming shard sub-ops (query string on the shard route above):
//!   PUT  /_simpaniz/shards/<bucket>/<key>/<idx>?seq=<n>           append chunk `seq`
//!   GET  /_simpaniz/shards/<bucket>/<key>/<idx>?offset=<o>&len=<n> ranged read
//!   GET  /_simpaniz/shards/<bucket>/<key>/<idx>?stat=1             body = decimal length
//!
//! Notes:
//!   - <key> may itself contain '/'; the trailing path segment after the
//!     last '/' is the shard index for shard ops.
//!   - Returns 200 with body for GET, 200 empty for PUT/DELETE, 404 for
//!     missing resources, 403 on auth failure, 400 on malformed paths.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("../http.zig");
const disk = @import("disk_store.zig");
const storage = @import("../storage.zig");
const membership_mod = @import("membership.zig");
const Membership = membership_mod.Membership;

const shards_prefix = "/_simpaniz/shards/";
const meta_prefix = "/_simpaniz/meta/";
const bucket_prefix = "/_simpaniz/bucket/";
const ping_path = "/_simpaniz/ping";
const join_path = "/_simpaniz/join";

pub fn matches(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "/_simpaniz/");
}

/// Constant-time equality.
fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

pub fn handle(
    req: *http.Request,
    data_dir: std.fs.Dir,
    cluster_secret: []const u8,
    max_body_bytes: usize,
    membership: ?*Membership,
) http.Response {
    // Auth.
    const auth = req.header("x-simpaniz-cluster-auth") orelse "";
    if (cluster_secret.len == 0 or !ctEql(auth, cluster_secret)) {
        return .{ .status = 403, .status_text = "Forbidden", .content_type = "text/plain", .body = .{ .bytes = "forbidden" } };
    }

    const a = req.arena.allocator();

    if (std.mem.eql(u8, req.path, ping_path)) {
        return switch (req.method) {
            .GET => doPing(a, membership),
            else => methodNotAllowed(),
        };
    }

    if (std.mem.eql(u8, req.path, join_path)) {
        return switch (req.method) {
            .POST => doJoin(req, a, membership, max_body_bytes),
            else => methodNotAllowed(),
        };
    }

    if (std.mem.startsWith(u8, req.path, shards_prefix)) {
        const rest = req.path[shards_prefix.len..];
        // rest = "<bucket>/<key>/<idx>"
        const last_slash = std.mem.lastIndexOfScalar(u8, rest, '/') orelse
            return badRequest("missing shard index");
        const idx_str = rest[last_slash + 1 ..];
        const bk = rest[0..last_slash];
        const first_slash = std.mem.indexOfScalar(u8, bk, '/') orelse
            return badRequest("missing key");
        const bucket = bk[0..first_slash];
        const key = bk[first_slash + 1 ..];
        const idx = std.fmt.parseInt(u8, idx_str, 10) catch return badRequest("bad index");

        return switch (req.method) {
            .PUT => blk: {
                if (queryParam(req.query, "seq")) |seq_str| {
                    const seq = std.fmt.parseInt(u64, seq_str, 10) catch return badRequest("bad seq");
                    break :blk doAppendShardChunk(req, a, data_dir, bucket, key, idx, seq, max_body_bytes);
                }
                break :blk doPutShard(req, a, data_dir, bucket, key, idx, max_body_bytes);
            },
            .GET => blk: {
                if (queryParam(req.query, "stat") != null) break :blk doStatShard(a, data_dir, bucket, key, idx);
                if (queryParam(req.query, "offset")) |off_str| {
                    const off = std.fmt.parseInt(u64, off_str, 10) catch return badRequest("bad offset");
                    const len_str = queryParam(req.query, "len") orelse return badRequest("missing len");
                    const len = std.fmt.parseInt(usize, len_str, 10) catch return badRequest("bad len");
                    break :blk doGetShardRange(a, data_dir, bucket, key, idx, off, len);
                }
                break :blk doGetShard(a, data_dir, bucket, key, idx);
            },
            .DELETE => doDelShard(data_dir, bucket, key, idx),
            else => methodNotAllowed(),
        };
    }

    if (std.mem.startsWith(u8, req.path, meta_prefix)) {
        const rest = req.path[meta_prefix.len..];
        const first_slash = std.mem.indexOfScalar(u8, rest, '/') orelse
            return badRequest("missing key");
        const bucket = rest[0..first_slash];
        const key = rest[first_slash + 1 ..];

        return switch (req.method) {
            .PUT => doPutMeta(req, a, data_dir, bucket, key, max_body_bytes),
            .GET => doGetMeta(a, data_dir, bucket, key),
            .DELETE => doDelMeta(data_dir, bucket, key),
            else => methodNotAllowed(),
        };
    }

    if (std.mem.startsWith(u8, req.path, bucket_prefix)) {
        const bucket = req.path[bucket_prefix.len..];
        if (bucket.len == 0 or std.mem.indexOfScalar(u8, bucket, '/') != null)
            return badRequest("bad bucket name");

        return switch (req.method) {
            .PUT => doPutBucket(data_dir, bucket),
            .DELETE => doDelBucket(data_dir, bucket),
            else => methodNotAllowed(),
        };
    }

    return .{ .status = 404, .status_text = "Not Found", .content_type = "text/plain", .body = .{ .bytes = "no such cluster route" } };
}

/// GET /_simpaniz/ping — returns this node's membership snapshot. This IS
/// the SWIM-lite gossip piggyback: every probe response carries the
/// responder's full node-list view.
fn doPing(a: Allocator, membership: ?*Membership) http.Response {
    const mem = membership orelse return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = "[]" } };
    const body = mem.snapshotJson(a) catch return serverError();
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

/// POST /_simpaniz/join {"id","host","port"} — adopt the announcing node
/// and reply with our current membership view so the joiner learns about
/// every node we already know (not just us).
fn doJoin(req: *http.Request, a: Allocator, membership: ?*Membership, max: usize) http.Response {
    const mem = membership orelse return badRequest("cluster membership not enabled");
    const body = req.readBodyAlloc(a, max) catch return serverError();

    var parsed = std.json.parseFromSlice(std.json.Value, a, body, .{}) catch return badRequest("bad json");
    defer parsed.deinit();
    if (parsed.value != .object) return badRequest("bad json");
    const obj = parsed.value.object;
    const id_v = obj.get("id") orelse return badRequest("missing id");
    const host_v = obj.get("host") orelse return badRequest("missing host");
    const port_v = obj.get("port") orelse return badRequest("missing port");
    if (id_v != .string or host_v != .string) return badRequest("bad id/host");
    const port: u16 = switch (port_v) {
        .integer => |v| if (v >= 0 and v <= std.math.maxInt(u16)) @intCast(v) else return badRequest("bad port"),
        else => return badRequest("bad port"),
    };

    _ = mem.addNode(id_v.string, host_v.string, port) catch return serverError();

    const snap = mem.snapshotJson(a) catch return serverError();
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = snap } };
}

fn doPutBucket(dir: std.fs.Dir, bucket: []const u8) http.Response {
    storage.createBucket(dir, bucket) catch |e| {
        if (e == error.BucketAlreadyExists) return ok();
        return serverError();
    };
    return ok();
}

fn doDelBucket(dir: std.fs.Dir, bucket: []const u8) http.Response {
    storage.deleteBucket(dir, bucket) catch |e| {
        if (e == error.BucketNotFound) return ok();
        return serverError();
    };
    return ok();
}

fn badRequest(msg: []const u8) http.Response {
    return .{ .status = 400, .status_text = "Bad Request", .content_type = "text/plain", .body = .{ .bytes = msg } };
}

fn methodNotAllowed() http.Response {
    return .{ .status = 405, .status_text = "Method Not Allowed", .content_type = "text/plain", .body = .{ .bytes = "method not allowed" } };
}

fn serverError() http.Response {
    return .{ .status = 500, .status_text = "Internal Server Error", .content_type = "text/plain", .body = .{ .bytes = "internal error" } };
}

fn ok() http.Response {
    return .{ .status = 200, .status_text = "OK", .content_type = "text/plain", .body = .{ .bytes = "ok" } };
}

fn notFound() http.Response {
    return .{ .status = 404, .status_text = "Not Found", .content_type = "text/plain", .body = .{ .bytes = "not found" } };
}

/// Find `name=value` in a raw (undecoded) query string joined by `&`.
fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

fn doAppendShardChunk(req: *http.Request, a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, seq: u64, max: usize) http.Response {
    const body = req.readBodyAlloc(a, max) catch return serverError();
    disk.appendShardChunk(dir, bucket, key, idx, seq, body) catch |e| {
        if (e == error.SeqMismatch) return badRequest("seq mismatch");
        return serverError();
    };
    return ok();
}

fn doGetShardRange(a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, offset: u64, len: usize) http.Response {
    const buf = a.alloc(u8, len) catch return serverError();
    const n = disk.getShardRange(dir, bucket, key, idx, offset, buf) catch |e| {
        if (e == error.ShardMissing) return notFound();
        return serverError();
    };
    return .{
        .status = 200,
        .status_text = "OK",
        .content_type = "application/octet-stream",
        .body = .{ .bytes = buf[0..n] },
    };
}

fn doStatShard(a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8) http.Response {
    const size = disk.statShard(dir, bucket, key, idx) catch |e| {
        if (e == error.ShardMissing) return notFound();
        return serverError();
    };
    const body = std.fmt.allocPrint(a, "{d}", .{size}) catch return serverError();
    return .{ .status = 200, .status_text = "OK", .content_type = "text/plain", .body = .{ .bytes = body } };
}

fn doPutShard(req: *http.Request, a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8, max: usize) http.Response {
    const body = req.readBodyAlloc(a, max) catch return serverError();
    disk.putShard(dir, bucket, key, idx, body) catch return serverError();
    return ok();
}

fn doGetShard(a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8) http.Response {
    const r = disk.getShard(dir, bucket, key, idx, a) catch return serverError();
    if (r) |bytes| return .{
        .status = 200,
        .status_text = "OK",
        .content_type = "application/octet-stream",
        .body = .{ .bytes = bytes },
    };
    return notFound();
}

fn doDelShard(dir: std.fs.Dir, bucket: []const u8, key: []const u8, idx: u8) http.Response {
    disk.deleteShard(dir, bucket, key, idx) catch return serverError();
    return ok();
}

fn doPutMeta(req: *http.Request, a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8, max: usize) http.Response {
    const body = req.readBodyAlloc(a, max) catch return serverError();
    disk.putMeta(dir, bucket, key, body) catch return serverError();
    return ok();
}

fn doGetMeta(a: Allocator, dir: std.fs.Dir, bucket: []const u8, key: []const u8) http.Response {
    const r = disk.getMeta(dir, bucket, key, a) catch return serverError();
    if (r) |bytes| return .{
        .status = 200,
        .status_text = "OK",
        .content_type = "application/json",
        .body = .{ .bytes = bytes },
    };
    return notFound();
}

fn doDelMeta(dir: std.fs.Dir, bucket: []const u8, key: []const u8) http.Response {
    disk.deleteMeta(dir, bucket, key) catch return serverError();
    return ok();
}

test "matches" {
    try std.testing.expect(matches("/_simpaniz/shards/b/k/0"));
    try std.testing.expect(matches("/_simpaniz/meta/b/k"));
    try std.testing.expect(!matches("/foo"));
}
