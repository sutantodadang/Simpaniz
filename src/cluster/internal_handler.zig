//! Handler for the internal cluster endpoint at `/_simpaniz/...`.
//! Authenticated via constant-time compare on the
//! `X-Simpaniz-Cluster-Auth` header; this bypasses S3 SigV4.
//!
//! Routes:
//!   PUT|GET|DELETE /_simpaniz/shards/<bucket>/<key>/<idx>
//!   PUT|GET|DELETE /_simpaniz/meta/<bucket>/<key>
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

const shards_prefix = "/_simpaniz/shards/";
const meta_prefix = "/_simpaniz/meta/";
const bucket_prefix = "/_simpaniz/bucket/";

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
) http.Response {
    // Auth.
    const auth = req.header("x-simpaniz-cluster-auth") orelse "";
    if (cluster_secret.len == 0 or !ctEql(auth, cluster_secret)) {
        return .{ .status = 403, .status_text = "Forbidden", .content_type = "text/plain", .body = .{ .bytes = "forbidden" } };
    }

    const a = req.arena.allocator();

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
            .PUT => doPutShard(req, a, data_dir, bucket, key, idx, max_body_bytes),
            .GET => doGetShard(a, data_dir, bucket, key, idx),
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
