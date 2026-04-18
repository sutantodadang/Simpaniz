//! S3 request router. Handles:
//!  - Path-style:   /<bucket>/<key>
//!  - Virtual-host: <bucket>.<host>/<key>  (Host header)
//!  - Subresources: ?delete, ?uploads, ?uploadId=, ?partNumber=
//!  - Health/metrics endpoints
//!  - CORS preflight (OPTIONS)
const std = @import("std");
const http = @import("http.zig");
const handlers = @import("handlers.zig");

pub const Routed = struct {
    response: http.Response,
};

pub fn route(req: *http.Request, ctx: handlers.HandlerContext) http.Response {
    // Special endpoints (path-only, no bucket).
    if (std.mem.eql(u8, req.path, "/healthz") or std.mem.eql(u8, req.path, "/health")) return handlers.health(ctx);
    if (std.mem.eql(u8, req.path, "/readyz")) return handlers.ready(ctx);
    if (std.mem.eql(u8, req.path, "/cluster/health") or std.mem.eql(u8, req.path, "/_simpaniz/cluster/health")) return handlers.clusterHealth(ctx);
    // /metrics is wired by the server (it has access to the Registry).

    // CORS preflight.
    if (req.method == .OPTIONS) {
        const cors_hdrs = ctx.allocator.dupe([]const u8, &.{
            "Access-Control-Allow-Origin: *",
            "Access-Control-Allow-Methods: GET, PUT, POST, DELETE, HEAD",
            "Access-Control-Allow-Headers: *",
            "Access-Control-Max-Age: 3000",
        }) catch &.{};
        return .{ .status = 200, .status_text = "OK", .extra_headers = cors_hdrs };
    }

    // Determine bucket + key. Virtual-host style if Host = "<bucket>.something".
    var bucket: []const u8 = "";
    var key: []const u8 = "";
    splitBucketKey(req, &bucket, &key);

    if (bucket.len == 0) {
        return switch (req.method) {
            .GET => handlers.listBuckets(ctx),
            else => methodNotAllowed(ctx, "/"),
        };
    }

    // ── Bucket-level (key empty) ─────────────────────────────────────────────
    if (key.len == 0) {
        if (req.method == .POST and hasFlag(req.query, "delete")) {
            return handlers.deleteMultiple(ctx, bucket, req);
        }
        if (hasFlag(req.query, "policy")) {
            return switch (req.method) {
                .PUT => handlers.putBucketPolicy(ctx, bucket, req),
                .GET => handlers.getBucketPolicy(ctx, bucket),
                .DELETE => handlers.deleteBucketPolicy(ctx, bucket),
                else => methodNotAllowed(ctx, bucket),
            };
        }
        if (hasFlag(req.query, "lifecycle")) {
            return switch (req.method) {
                .PUT => handlers.putBucketLifecycle(ctx, bucket, req),
                .GET => handlers.getBucketLifecycle(ctx, bucket),
                .DELETE => handlers.deleteBucketLifecycle(ctx, bucket),
                else => methodNotAllowed(ctx, bucket),
            };
        }
        if (hasFlag(req.query, "versioning")) {
            return switch (req.method) {
                .PUT => handlers.putBucketVersioning(ctx, bucket, req),
                .GET => handlers.getBucketVersioning(ctx, bucket),
                else => methodNotAllowed(ctx, bucket),
            };
        }
        if (hasFlag(req.query, "object-lock")) {
            return switch (req.method) {
                .PUT => handlers.putBucketObjectLockConfig(ctx, bucket, req),
                .GET => handlers.getBucketObjectLockConfig(ctx, bucket),
                else => methodNotAllowed(ctx, bucket),
            };
        }
        if (req.method == .GET and hasFlag(req.query, "versions")) {
            return handlers.listObjectVersions(ctx, bucket, req);
        }
        if (req.method == .GET and hasFlag(req.query, "uploads")) {
            return handlers.listMultipartUploads(ctx, bucket);
        }
        return switch (req.method) {
            .PUT => handlers.createBucket(ctx, bucket),
            .DELETE => handlers.deleteBucket(ctx, bucket),
            .HEAD => handlers.headBucket(ctx, bucket),
            .GET => handlers.listObjects(ctx, bucket, req.query),
            else => methodNotAllowed(ctx, bucket),
        };
    }

    // ── Object-level multipart subresources ──────────────────────────────────
    if (req.method == .POST and hasFlag(req.query, "uploads")) {
        return handlers.createMultipartUpload(ctx, bucket, key, req);
    }
    if (qp(req.query, "uploadId")) |upload_id| {
        if (qp(req.query, "partNumber")) |pn_s| {
            const pn = std.fmt.parseInt(u32, pn_s, 10) catch 0;
            if (req.method == .PUT) {
                if (req.header("x-amz-copy-source")) |src| {
                    const range_hdr = req.header("x-amz-copy-source-range") orelse "";
                    return handlers.uploadPartCopy(ctx, bucket, upload_id, pn, src, range_hdr);
                }
                return handlers.uploadPart(ctx, bucket, key, upload_id, pn, req);
            }
        }
        return switch (req.method) {
            .POST => handlers.completeMultipart(ctx, bucket, key, upload_id, req),
            .DELETE => handlers.abortMultipart(ctx, bucket, key, upload_id),
            .GET => handlers.listParts(ctx, bucket, key, upload_id),
            else => methodNotAllowed(ctx, key),
        };
    }

    // ── Object tagging subresource ───────────────────────────────────────────
    if (hasFlag(req.query, "tagging")) {
        return switch (req.method) {
            .PUT => handlers.putObjectTagging(ctx, bucket, key, req),
            .GET => handlers.getObjectTagging(ctx, bucket, key),
            .DELETE => handlers.deleteObjectTagging(ctx, bucket, key),
            else => methodNotAllowed(ctx, key),
        };
    }

    // ── Object Lock retention ────────────────────────────────────────────────
    if (hasFlag(req.query, "retention")) {
        return switch (req.method) {
            .PUT => handlers.putObjectRetention(ctx, bucket, key, req),
            .GET => handlers.getObjectRetention(ctx, bucket, key),
            else => methodNotAllowed(ctx, key),
        };
    }

    // ── Object Lock legal hold ───────────────────────────────────────────────
    if (hasFlag(req.query, "legal-hold")) {
        return switch (req.method) {
            .PUT => handlers.putObjectLegalHold(ctx, bucket, key, req),
            .GET => handlers.getObjectLegalHold(ctx, bucket, key),
            else => methodNotAllowed(ctx, key),
        };
    }

    // ── Plain object ops ─────────────────────────────────────────────────────
    return switch (req.method) {
        .PUT => handlers.putObject(ctx, bucket, key, req),
        .GET => handlers.getObject(ctx, bucket, key, req),
        .HEAD => handlers.headObject(ctx, bucket, key, req),
        .DELETE => handlers.deleteObject(ctx, bucket, key, req),
        else => methodNotAllowed(ctx, key),
    };
}

fn methodNotAllowed(ctx: handlers.HandlerContext, resource: []const u8) http.Response {
    const xml = @import("xml.zig");
    const body = xml.buildError(ctx.allocator, "MethodNotAllowed", "Method not allowed.", resource, ctx.request_id) catch "";
    return .{ .status = 405, .status_text = "Method Not Allowed", .body = .{ .bytes = body } };
}

fn splitBucketKey(req: *const http.Request, bucket: *[]const u8, key: *[]const u8) void {
    // Try virtual-host style: Host header begins with <bucket>.
    if (req.header("host")) |host_full| {
        const host = if (std.mem.indexOfScalar(u8, host_full, ':')) |c| host_full[0..c] else host_full;
        if (std.mem.indexOfScalar(u8, host, '.')) |dot| {
            // Plausible bucket-as-subdomain (skip raw IP-like first label).
            const candidate = host[0..dot];
            if (looksLikeBucket(candidate)) {
                bucket.* = candidate;
                const path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
                key.* = path;
                return;
            }
        }
    }
    // Path-style: /<bucket>/<key...>
    const path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
    if (std.mem.indexOfScalar(u8, path, '/')) |sep| {
        bucket.* = path[0..sep];
        key.* = path[sep + 1 ..];
    } else {
        bucket.* = path;
        key.* = "";
    }
}

fn looksLikeBucket(s: []const u8) bool {
    if (s.len < 3 or s.len > 63) return false;
    if (std.mem.eql(u8, s, "www")) return false;
    var dots: usize = 0;
    for (s) |c| {
        if (c == '.') dots += 1;
        if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '-' or c == '.')) return false;
    }
    // Reject pure numeric/IP-ish.
    if (dots > 0) return true;
    for (s) |c| if (!std.ascii.isDigit(c)) return true;
    return false;
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

fn hasFlag(query: []const u8, key: []const u8) bool {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        const name = if (std.mem.indexOfScalar(u8, param, '=')) |eq| param[0..eq] else param;
        if (std.mem.eql(u8, name, key)) return true;
    }
    return false;
}

test "splitBucketKey path-style" {
    var req: http.Request = undefined;
    req.path = "/my-bucket/foo/bar";
    req.headers = &.{};
    var b: []const u8 = "";
    var k: []const u8 = "";
    splitBucketKey(&req, &b, &k);
    try std.testing.expectEqualStrings("my-bucket", b);
    try std.testing.expectEqualStrings("foo/bar", k);
}

test "splitBucketKey bucket only" {
    var req: http.Request = undefined;
    req.path = "/my-bucket";
    req.headers = &.{};
    var b: []const u8 = "";
    var k: []const u8 = "";
    splitBucketKey(&req, &b, &k);
    try std.testing.expectEqualStrings("my-bucket", b);
    try std.testing.expectEqualStrings("", k);
}

test "hasFlag detects bare key" {
    try std.testing.expect(hasFlag("delete", "delete"));
    try std.testing.expect(hasFlag("foo&delete", "delete"));
    try std.testing.expect(!hasFlag("delete-marker", "delete"));
}
