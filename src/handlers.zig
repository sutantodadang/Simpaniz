//! S3-compatible request handlers.
//!
//! Handlers receive a parsed Request (with body still on the wire) and a
//! handler context (data dir, allocator, request id). Each handler returns
//! a Response that the server writes to the client. Streaming responses
//! (GET object) carry a file slice in `Body.file` so the server can stream
//! without buffering.
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const storage = @import("storage.zig");
const xml = @import("xml.zig");
const util = @import("util.zig");
const cluster = @import("cluster.zig");

pub const HandlerContext = struct {
    data_dir: std.fs.Dir,
    allocator: Allocator,
    request_id: []const u8,
    region: []const u8,
    /// SSE-S3 master key (32 bytes), or null if not configured.
    master_key: ?*const [32]u8 = null,
    /// Cluster runtime, or null when running single-node.
    cluster: ?*cluster.ClusterRuntime = null,
    /// Body cap (mirrors server config) — used by cluster PUT to bound buffer.
    max_body_bytes: usize = 5 * 1024 * 1024 * 1024,
};

// ── Bucket-level ─────────────────────────────────────────────────────────────

pub fn createBucket(ctx: HandlerContext, bucket: []const u8) http.Response {
    storage.createBucket(ctx.data_dir, bucket) catch |e| return mapErr(ctx, e, bucket);
    if (ctx.cluster) |cr| {
        cr.replicateBucket(bucket, .create) catch {};
    }
    const loc_hdr = std.fmt.allocPrint(ctx.allocator, "Location: /{s}", .{bucket}) catch return ok();
    const hdrs = ctx.allocator.dupe([]const u8, &.{loc_hdr}) catch return ok();
    return .{ .status = 200, .status_text = "OK", .extra_headers = hdrs };
}

pub fn deleteBucket(ctx: HandlerContext, bucket: []const u8) http.Response {
    storage.deleteBucket(ctx.data_dir, bucket) catch |e| return mapErr(ctx, e, bucket);
    if (ctx.cluster) |cr| {
        cr.replicateBucket(bucket, .delete) catch {};
    }
    return noContent();
}

pub fn headBucket(ctx: HandlerContext, bucket: []const u8) http.Response {
    if (storage.bucketExists(ctx.data_dir, bucket)) {
        const reg_hdr = std.fmt.allocPrint(ctx.allocator, "x-amz-bucket-region: {s}", .{ctx.region}) catch return ok();
        const hdrs = ctx.allocator.dupe([]const u8, &.{reg_hdr}) catch return ok();
        return .{ .status = 200, .status_text = "OK", .extra_headers = hdrs };
    }
    return mapErr(ctx, error.BucketNotFound, bucket);
}

pub fn listBuckets(ctx: HandlerContext) http.Response {
    const buckets = storage.listBuckets(ctx.data_dir, ctx.allocator) catch |e| return mapErr(ctx, e, "/");
    var infos = ctx.allocator.alloc(xml.BucketInfo, buckets.len) catch return internal(ctx, "/");
    for (buckets, 0..) |b, i| {
        var lm_buf: [32]u8 = undefined;
        const lm = util.formatIso8601(&lm_buf, b.creation_ns);
        infos[i] = .{ .name = b.name, .creation_date = ctx.allocator.dupe(u8, lm) catch "" };
    }
    const body = xml.buildListBuckets(ctx.allocator, infos) catch return internal(ctx, "/");
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

pub fn listObjects(ctx: HandlerContext, bucket: []const u8, query: []const u8) http.Response {
    const prefix = qp(query, "prefix") orelse "";
    const delimiter = qp(query, "delimiter") orelse "";
    const cont_token = qp(query, "continuation-token") orelse "";
    const start_after = qp(query, "start-after") orelse "";
    const max_keys_s = qp(query, "max-keys") orelse "1000";
    const max_keys = std.fmt.parseInt(usize, max_keys_s, 10) catch 1000;

    const dec_prefix = util.urlDecode(ctx.allocator, prefix) catch prefix;
    const dec_delim = util.urlDecode(ctx.allocator, delimiter) catch delimiter;
    const dec_cont = util.urlDecode(ctx.allocator, cont_token) catch cont_token;
    const dec_start = util.urlDecode(ctx.allocator, start_after) catch start_after;

    const page = storage.listObjects(ctx.data_dir, ctx.allocator, bucket, .{
        .prefix = dec_prefix,
        .delimiter = dec_delim,
        .continuation_token = dec_cont,
        .start_after = dec_start,
        .max_keys = max_keys,
    }) catch |e| return mapErr(ctx, e, bucket);

    const body = xml.buildListObjects(ctx.allocator, .{
        .bucket = bucket,
        .prefix = dec_prefix,
        .delimiter = dec_delim,
        .continuation_token = dec_cont,
        .next_continuation_token = page.next_continuation_token,
        .start_after = dec_start,
        .max_keys = max_keys,
        .is_truncated = page.is_truncated,
        .key_count = page.objects.len + page.common_prefixes.len,
        .objects = page.objects,
        .common_prefixes = page.common_prefixes,
    }) catch return internal(ctx, bucket);

    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

// ── Object-level ─────────────────────────────────────────────────────────────

pub fn putObject(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    if (ctx.cluster) |cr| return clusterPutObject(ctx, cr, bucket, key, req);

    // CopyObject when x-amz-copy-source is present.
    if (req.header("x-amz-copy-source")) |src| {
        return copyObject(ctx, bucket, key, src);
    }

    // Object Lock: block overwrite if currently protected.
    if (objectIsCurrentlyProtected(ctx, bucket, key, req)) |resp| return resp;

    // Versioning snapshot: if Enabled, copy current version aside before overwrite.
    snapshotIfVersioned(ctx, bucket, key);

    const ct = req.content_type;
    const md5_hdr = req.header("content-md5") orelse "";
    const sha_hdr = req.header("x-amz-content-sha256") orelse "";

    // Pre-PUT marker: was there an existing object? Default-retention only
    // applies on the *first* write of a key, matching AWS semantics.
    const had_existing = blk: {
        _ = storage.headObject(ctx.data_dir, ctx.allocator, bucket, key) catch break :blk false;
        break :blk true;
    };

    // SSE-S3 requested via x-amz-server-side-encryption: AES256.
    var sse_key: ?*const [32]u8 = null;
    if (req.header("x-amz-server-side-encryption")) |sse_alg| {
        if (!std.mem.eql(u8, sse_alg, "AES256")) {
            return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Unsupported SSE algorithm", key);
        }
        if (ctx.master_key) |mk| {
            sse_key = mk;
        } else {
            return errResp(ctx, 501, "Not Implemented", "ServerSideEncryptionConfigurationNotFoundError", "SSE not configured (set SIMPANIZ_MASTER_KEY)", key);
        }
    }

    const meta = storage.putObjectStreaming(ctx.data_dir, ctx.allocator, .{
        .bucket = bucket,
        .key = key,
        .content_type = ct,
        .content_length = req.content_length,
        .expected_md5_b64 = md5_hdr,
        .expected_sha256_hex = sha_hdr,
        .master_key = sse_key,
    }, req.body_reader) catch |e| return mapErr(ctx, e, key);
    // Tell the server we consumed the body so it doesn't try to drain.
    req.body_consumed = req.content_length;

    // Auto-apply bucket default retention on first PUT, when configured and
    // the request didn't carry an explicit x-amz-object-lock-mode header.
    if (!had_existing and req.header("x-amz-object-lock-mode") == null) {
        applyDefaultRetention(ctx, bucket, key);
    }

    var hdrs_list = std.ArrayList([]const u8){};
    hdrs_list.append(ctx.allocator, std.fmt.allocPrint(ctx.allocator, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
    if (sse_key != null) {
        hdrs_list.append(ctx.allocator, std.fmt.allocPrint(ctx.allocator, "x-amz-server-side-encryption: AES256", .{}) catch "") catch {};
    }
    return .{ .status = 200, .status_text = "OK", .extra_headers = hdrs_list.toOwnedSlice(ctx.allocator) catch &.{} };
}

fn applyDefaultRetention(ctx: HandlerContext, bucket: []const u8, key: []const u8) void {
    const cfg = storage.getBucketObjectLock(ctx.data_dir, ctx.allocator, bucket) catch return;
    const c = cfg orelse return;
    if (!c.enabled) return;
    const mode = c.default_mode orelse return;
    if (c.default_days == 0) return;
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return;
    defer bd.close();
    const now_ns: i128 = std.time.nanoTimestamp();
    const ns_per_day: i128 = std.time.ns_per_s * 86400;
    const until_ns: i128 = now_ns + ns_per_day * @as(i128, c.default_days);
    storage.putObjectRetention(bd, ctx.allocator, key, .{ .mode = mode, .retain_until_ns = until_ns }) catch {};
}

pub fn copyObject(ctx: HandlerContext, dst_bucket: []const u8, dst_key: []const u8, raw_src: []const u8) http.Response {
    // Parse "/srcBucket/srcKey" or "srcBucket/srcKey".
    const src = if (raw_src.len > 0 and raw_src[0] == '/') raw_src[1..] else raw_src;
    const slash = std.mem.indexOfScalar(u8, src, '/') orelse return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad x-amz-copy-source", dst_key);
    const src_bucket = src[0..slash];
    const enc_src_key = src[slash + 1 ..];
    const src_key = util.urlDecode(ctx.allocator, enc_src_key) catch enc_src_key;

    const meta = storage.copyObject(ctx.data_dir, ctx.allocator, src_bucket, src_key, dst_bucket, dst_key, null) catch |e| return mapErr(ctx, e, dst_key);
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, meta.mtime_ns);
    const body = xml.buildCopyObjectResult(ctx.allocator, meta.etag, lm) catch return internal(ctx, dst_key);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

pub fn getObject(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    if (ctx.cluster) |cr| return clusterGetObject(ctx, cr, bucket, key, req);

    // ?versionId= — serve a specific historical snapshot.
    if (qp(req.query, "versionId")) |vid| {
        return getObjectVersion(ctx, bucket, key, vid);
    }

    const opened = storage.openObject(ctx.data_dir, ctx.allocator, bucket, key) catch |e| return mapErr(ctx, e, key);
    var file = opened.file;
    const meta = opened.meta;
    const total: u64 = meta.size;

    // Conditional headers.
    if (req.header("if-none-match")) |inm| {
        const stripped = std.mem.trim(u8, inm, "\"");
        if (std.mem.eql(u8, stripped, meta.etag)) {
            file.close();
            return .{ .status = 304, .status_text = "Not Modified" };
        }
    }
    if (req.header("if-match")) |im| {
        const stripped = std.mem.trim(u8, im, "\"");
        if (!std.mem.eql(u8, stripped, meta.etag)) {
            file.close();
            return .{ .status = 412, .status_text = "Precondition Failed" };
        }
    }

    // SSE: Range over encrypted objects is not supported in this cut.
    if (meta.encryption != null and req.header("range") != null) {
        file.close();
        return errResp(ctx, 501, "Not Implemented", "NotImplemented", "Range requests on SSE-encrypted objects are not yet supported", key);
    }

    // SSE: stream-decrypt path.
    if (meta.encryption) |enc| {
        const mk = ctx.master_key orelse {
            file.close();
            return errResp(ctx, 500, "Internal Server Error", "InternalError", "Master key not configured but object is encrypted", key);
        };
        const sse = @import("storage/sse.zig");
        const sse_internal = @import("storage/internal.zig");
        const wrapped_raw = sse_internal.decodeBase64(ctx.allocator, enc.wrapped_dek_b64) catch {
            file.close();
            return internal(ctx, key);
        };
        const nonce_raw = sse_internal.decodeBase64(ctx.allocator, enc.wrap_nonce_b64) catch {
            file.close();
            return internal(ctx, key);
        };
        if (wrapped_raw.len != sse.wrapped_dek_len or nonce_raw.len != sse.nonce_size) {
            file.close();
            return internal(ctx, key);
        }
        const wrapped_arr: *const [sse.wrapped_dek_len]u8 = wrapped_raw[0..sse.wrapped_dek_len];
        const nonce_arr: *const [sse.nonce_size]u8 = nonce_raw[0..sse.nonce_size];
        const dek = sse.unwrapDek(mk, wrapped_arr, nonce_arr) catch {
            file.close();
            return errResp(ctx, 500, "Internal Server Error", "InternalError", "Failed to unwrap data key", key);
        };

        var hdrs_list = std.ArrayList([]const u8){};
        const a = ctx.allocator;
        hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
        var lm_buf: [32]u8 = undefined;
        const lm = util.formatIso8601(&lm_buf, meta.mtime_ns);
        hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
        hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-server-side-encryption: AES256", .{}) catch "") catch {};

        return .{
            .status = 200,
            .status_text = "OK",
            .content_type = meta.content_type,
            .body = .{ .encrypted_file = .{ .file = file, .plaintext_length = total, .dek = dek, .owns_file = true } },
            .extra_headers = hdrs_list.toOwnedSlice(a) catch &.{},
        };
    }

    var status: u16 = 200;
    var status_text: []const u8 = "OK";
    var offset: u64 = 0;
    var length: u64 = total;

    if (req.header("range")) |range| {
        if (parseRange(range, total)) |r| {
            offset = r.start;
            length = r.end - r.start + 1;
            status = 206;
            status_text = "Partial Content";
        }
    }

    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
    hdrs_list.append(a, std.fmt.allocPrint(a, "Accept-Ranges: bytes", .{}) catch "") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, meta.mtime_ns);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
    if (status == 206) {
        hdrs_list.append(a, std.fmt.allocPrint(a, "Content-Range: bytes {d}-{d}/{d}", .{ offset, offset + length - 1, total }) catch "") catch {};
    }
    const hdrs = hdrs_list.toOwnedSlice(a) catch &.{};

    return .{
        .status = status,
        .status_text = status_text,
        .content_type = meta.content_type,
        .body = .{ .file = .{ .file = file, .offset = offset, .length = length, .owns_file = true } },
        .extra_headers = hdrs,
    };
}

pub fn headObject(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    if (ctx.cluster) |cr| return clusterHeadObject(ctx, cr, bucket, key);

    if (qp(req.query, "versionId")) |vid| {
        return headObjectVersion(ctx, bucket, key, vid);
    }

    const meta = storage.headObject(ctx.data_dir, ctx.allocator, bucket, key) catch |e| return mapErr(ctx, e, key);
    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-meta-content-length: {d}", .{meta.size}) catch "") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, meta.mtime_ns);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
    // Override content-length so HEAD reports object size, not 0 body.
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-actual-length: {d}", .{meta.size}) catch "") catch {};
    const hdrs = hdrs_list.toOwnedSlice(a) catch &.{};
    return .{ .status = 200, .status_text = "OK", .content_type = meta.content_type, .extra_headers = hdrs };
}

pub fn deleteObject(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    if (ctx.cluster) |cr| return clusterDeleteObject(ctx, cr, bucket, key);

    // ?versionId= — permanently delete that specific snapshot.
    if (qp(req.query, "versionId")) |vid| {
        var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
        defer bd.close();
        storage.deleteObjectVersion(bd, ctx.allocator, key, vid) catch |e| return mapErr(ctx, e, key);
        const vid_hdr = std.fmt.allocPrint(ctx.allocator, "x-amz-version-id: {s}", .{vid}) catch "";
        const hdrs = ctx.allocator.dupe([]const u8, &.{vid_hdr}) catch &.{};
        return .{ .status = 204, .status_text = "No Content", .extra_headers = hdrs };
    }

    if (objectIsCurrentlyProtectedNoReq(ctx, bucket, key, false)) {
        return errResp(ctx, 403, "Forbidden", "AccessDenied", "Object is WORM-protected (retention or legal hold)", key);
    }

    // If versioning is enabled, snapshot then write a delete marker instead
    // of physically removing the current object.
    const vstate = storage.getBucketVersioning(ctx.data_dir, bucket) catch .disabled;
    if (vstate == .enabled) {
        snapshotIfVersioned(ctx, bucket, key);
        var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
        defer bd.close();
        const vid = storage.addDeleteMarker(bd, ctx.allocator, key) catch |e| return mapErr(ctx, e, key);
        storage.deleteObject(ctx.data_dir, ctx.allocator, bucket, key) catch {};
        const vid_hdr = std.fmt.allocPrint(ctx.allocator, "x-amz-version-id: {s}", .{vid}) catch "";
        const dm_hdr = std.fmt.allocPrint(ctx.allocator, "x-amz-delete-marker: true", .{}) catch "";
        const hdrs = ctx.allocator.dupe([]const u8, &.{ vid_hdr, dm_hdr }) catch &.{};
        return .{ .status = 204, .status_text = "No Content", .extra_headers = hdrs };
    }

    snapshotIfVersioned(ctx, bucket, key);
    storage.deleteObject(ctx.data_dir, ctx.allocator, bucket, key) catch |e| switch (e) {
        error.ObjectNotFound => {}, // S3 returns 204 even if missing.
        else => return mapErr(ctx, e, key),
    };
    return noContent();
}

fn snapshotIfVersioned(ctx: HandlerContext, bucket: []const u8, key: []const u8) void {
    const state = storage.getBucketVersioning(ctx.data_dir, bucket) catch return;
    if (state != .enabled) return;
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return;
    defer bd.close();
    _ = storage.snapshotCurrentVersion(bd, ctx.allocator, key) catch return;
}

fn objectIsCurrentlyProtectedNoReq(ctx: HandlerContext, bucket: []const u8, key: []const u8, bypass: bool) bool {
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return false;
    defer bd.close();
    const now: i128 = std.time.nanoTimestamp();
    return storage.objectIsProtected(bd, ctx.allocator, key, now, bypass);
}

fn objectIsCurrentlyProtected(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) ?http.Response {
    const bypass = blk: {
        const hdr = req.header("x-amz-bypass-governance-retention") orelse break :blk false;
        break :blk std.mem.eql(u8, hdr, "true") or std.mem.eql(u8, hdr, "True");
    };
    if (objectIsCurrentlyProtectedNoReq(ctx, bucket, key, bypass)) {
        return errResp(ctx, 403, "Forbidden", "AccessDenied", "Object is WORM-protected (retention or legal hold)", key);
    }
    return null;
}

pub fn putBucketVersioning(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 4096) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", bucket);
    storage.putBucketVersioning(ctx.data_dir, bucket, body) catch |e| switch (e) {
        error.InvalidArgument => return errResp(ctx, 400, "Bad Request", "MalformedXML", "Bad versioning XML", bucket),
        else => return mapErr(ctx, e, bucket),
    };
    return ok();
}

pub fn getBucketVersioning(ctx: HandlerContext, bucket: []const u8) http.Response {
    const state = storage.getBucketVersioning(ctx.data_dir, bucket) catch |e| return mapErr(ctx, e, bucket);
    const status_xml = switch (state) {
        .disabled => "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        .enabled => "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
        .suspended => "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Suspended</Status></VersioningConfiguration>",
    };
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = status_xml } };
}

pub fn putBucketObjectLockConfig(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 4096) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", bucket);
    storage.putBucketObjectLock(ctx.data_dir, ctx.allocator, bucket, body) catch |e| return mapErr(ctx, e, bucket);
    return ok();
}

pub fn getBucketObjectLockConfig(ctx: HandlerContext, bucket: []const u8) http.Response {
    const cfg = storage.getBucketObjectLock(ctx.data_dir, ctx.allocator, bucket) catch |e| return mapErr(ctx, e, bucket);
    const c = cfg orelse return errResp(ctx, 404, "Not Found", "ObjectLockConfigurationNotFoundError", "No object lock config", bucket);
    const xml_body = storage.buildBucketObjectLockXml(ctx.allocator, c) catch return internal(ctx, bucket);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = xml_body } };
}

pub fn listObjectVersions(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    if (ctx.cluster != null) {
        return errResp(ctx, 501, "Not Implemented", "NotImplemented", "ListObjectVersions not supported in cluster mode", bucket);
    }
    var bd = ctx.data_dir.openDir(bucket, .{ .iterate = true }) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    const prefix = qp(req.query, "prefix") orelse "";
    const entries = storage.listObjectVersions(bd, ctx.allocator, prefix) catch return internal(ctx, bucket);
    defer {
        for (entries) |e| {
            ctx.allocator.free(e.key);
            ctx.allocator.free(e.etag);
        }
        ctx.allocator.free(entries);
    }
    var infos = std.ArrayList(xml.VersionInfo){};
    defer infos.deinit(ctx.allocator);
    var lm_bufs = std.ArrayList([32]u8){};
    defer lm_bufs.deinit(ctx.allocator);
    lm_bufs.ensureTotalCapacity(ctx.allocator, entries.len) catch return internal(ctx, bucket);
    for (entries) |e| {
        lm_bufs.append(ctx.allocator, undefined) catch return internal(ctx, bucket);
        const idx = lm_bufs.items.len - 1;
        const lm = util.formatIso8601(&lm_bufs.items[idx], e.mtime_ns);
        infos.append(ctx.allocator, .{
            .key = e.key,
            .version_id = &e.version_id,
            .is_delete_marker = e.is_delete_marker,
            .is_latest = e.is_latest,
            .last_modified = lm,
            .etag = e.etag,
            .size = e.size,
        }) catch return internal(ctx, bucket);
    }
    const body = xml.buildListObjectVersions(ctx.allocator, bucket, prefix, infos.items) catch return internal(ctx, bucket);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = body } };
}

fn getObjectVersion(ctx: HandlerContext, bucket: []const u8, key: []const u8, vid: []const u8) http.Response {
    if (vid.len != 16) return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad versionId", key);
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    const f_opt = storage.openVersionData(bd, ctx.allocator, key, vid) catch return internal(ctx, key);
    var file = f_opt orelse return errResp(ctx, 404, "Not Found", "NoSuchVersion", "Version not found", key);
    const stat = file.stat() catch {
        file.close();
        return internal(ctx, key);
    };
    const total: u64 = stat.size;

    var ct: []const u8 = "application/octet-stream";
    var etag_for_hdr: []const u8 = "";
    if (storage.readObjectVersionMeta(bd, ctx.allocator, key, vid)) |maybe_meta| {
        if (maybe_meta) |json| {
            defer ctx.allocator.free(json);
            if (extractJsonString(json, "content_type")) |c| ct = ctx.allocator.dupe(u8, c) catch ct;
            if (extractJsonString(json, "etag")) |e| etag_for_hdr = ctx.allocator.dupe(u8, e) catch "";
        }
    } else |_| {}

    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-version-id: {s}", .{vid}) catch "") catch {};
    if (etag_for_hdr.len > 0) hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{etag_for_hdr}) catch "") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, stat.mtime);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};

    return .{
        .status = 200,
        .status_text = "OK",
        .content_type = ct,
        .body = .{ .file = .{ .file = file, .offset = 0, .length = total, .owns_file = true } },
        .extra_headers = hdrs_list.toOwnedSlice(a) catch &.{},
    };
}

fn headObjectVersion(ctx: HandlerContext, bucket: []const u8, key: []const u8, vid: []const u8) http.Response {
    if (vid.len != 16) return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad versionId", key);
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    const f_opt = storage.openVersionData(bd, ctx.allocator, key, vid) catch return internal(ctx, key);
    var file = f_opt orelse return errResp(ctx, 404, "Not Found", "NoSuchVersion", "Version not found", key);
    defer file.close();
    const stat = file.stat() catch return internal(ctx, key);

    var ct: []const u8 = "application/octet-stream";
    var etag_for_hdr: []const u8 = "";
    if (storage.readObjectVersionMeta(bd, ctx.allocator, key, vid)) |maybe_meta| {
        if (maybe_meta) |json| {
            defer ctx.allocator.free(json);
            if (extractJsonString(json, "content_type")) |c| ct = ctx.allocator.dupe(u8, c) catch ct;
            if (extractJsonString(json, "etag")) |e| etag_for_hdr = ctx.allocator.dupe(u8, e) catch "";
        }
    } else |_| {}

    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-version-id: {s}", .{vid}) catch "") catch {};
    if (etag_for_hdr.len > 0) hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{etag_for_hdr}) catch "") catch {};
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-actual-length: {d}", .{stat.size}) catch "") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, stat.mtime);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
    return .{ .status = 200, .status_text = "OK", .content_type = ct, .extra_headers = hdrs_list.toOwnedSlice(a) catch &.{} };
}

pub fn clusterHealth(ctx: HandlerContext) http.Response {
    if (ctx.cluster == null) {
        return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = "{\"mode\":\"single\"}" } };
    }
    const cr = ctx.cluster.?;
    var buf = std.ArrayList(u8){};
    defer buf.deinit(ctx.allocator);
    buf.appendSlice(ctx.allocator, "{\"mode\":\"cluster\",\"self\":\"") catch return internal(ctx, "/cluster/health");
    buf.appendSlice(ctx.allocator, cr.config.node_id) catch {};
    buf.appendSlice(ctx.allocator, "\",\"peers\":[") catch {};
    var first = true;
    for (cr.config.peers) |p| {
        if (!first) buf.appendSlice(ctx.allocator, ",") catch {};
        first = false;
        buf.appendSlice(ctx.allocator, "{\"node\":\"") catch {};
        buf.appendSlice(ctx.allocator, p.id) catch {};
        buf.appendSlice(ctx.allocator, "\"}") catch {};
    }
    buf.appendSlice(ctx.allocator, "]}") catch {};
    const body = buf.toOwnedSlice(ctx.allocator) catch return internal(ctx, "/cluster/health");
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

fn extractJsonString(json: []const u8, field: []const u8) ?[]const u8 {
    var key_buf: [128]u8 = undefined;
    const k = std.fmt.bufPrint(&key_buf, "\"{s}\":\"", .{field}) catch return null;
    const i = std.mem.indexOf(u8, json, k) orelse return null;
    const s = i + k.len;
    const e = std.mem.indexOfScalarPos(u8, json, s, '"') orelse return null;
    return json[s..e];
}

pub fn putObjectRetention(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 4096) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", key);
    const mode = extractTag(body, "Mode") orelse return errResp(ctx, 400, "Bad Request", "MalformedXML", "Missing Mode", key);
    const until_iso = extractTag(body, "RetainUntilDate") orelse return errResp(ctx, 400, "Bad Request", "MalformedXML", "Missing RetainUntilDate", key);
    const until_ns = util.parseIso8601(until_iso) catch return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad RetainUntilDate", key);
    const m: storage.RetentionMode = if (std.mem.eql(u8, mode, "COMPLIANCE")) .compliance else .governance;

    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    storage.putObjectRetention(bd, ctx.allocator, key, .{ .mode = m, .retain_until_ns = until_ns }) catch |e| return mapErr(ctx, e, key);
    return ok();
}

pub fn getObjectRetention(ctx: HandlerContext, bucket: []const u8, key: []const u8) http.Response {
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    const ret = (storage.getObjectRetention(bd, ctx.allocator, key) catch |e| return mapErr(ctx, e, key)) orelse {
        return errResp(ctx, 404, "Not Found", "NoSuchObjectLockConfiguration", "No retention set", key);
    };
    var iso_buf: [32]u8 = undefined;
    const iso = util.formatIso8601(&iso_buf, ret.retain_until_ns);
    const mode_str = switch (ret.mode) { .governance => "GOVERNANCE", .compliance => "COMPLIANCE" };
    const body = std.fmt.allocPrint(ctx.allocator, "<Retention><Mode>{s}</Mode><RetainUntilDate>{s}</RetainUntilDate></Retention>", .{ mode_str, iso }) catch return internal(ctx, key);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = body } };
}

pub fn putObjectLegalHold(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 4096) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", key);
    const status = extractTag(body, "Status") orelse return errResp(ctx, 400, "Bad Request", "MalformedXML", "Missing Status", key);
    const on = std.mem.eql(u8, status, "ON");
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    storage.putObjectLegalHold(bd, ctx.allocator, key, on) catch |e| return mapErr(ctx, e, key);
    return ok();
}

pub fn getObjectLegalHold(ctx: HandlerContext, bucket: []const u8, key: []const u8) http.Response {
    var bd = ctx.data_dir.openDir(bucket, .{}) catch return errResp(ctx, 404, "Not Found", "NoSuchBucket", "Bucket missing", bucket);
    defer bd.close();
    const on = storage.objectLegalHoldOn(bd, ctx.allocator, key);
    const status = if (on) "ON" else "OFF";
    const body = std.fmt.allocPrint(ctx.allocator, "<LegalHold><Status>{s}</Status></LegalHold>", .{status}) catch return internal(ctx, key);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = body } };
}

fn extractTag(body: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const i = std.mem.indexOf(u8, body, open) orelse return null;
    const start = i + open.len;
    const e = std.mem.indexOfPos(u8, body, start, close) orelse return null;
    return std.mem.trim(u8, body[start..e], " \t\r\n");
}

pub fn deleteMultiple(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 1024 * 1024) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", bucket);
    const keys = xml.collectTagValues(ctx.allocator, body, "Key") catch return internal(ctx, bucket);

    var deleted = std.ArrayList(xml.DeleteResultEntry){};
    var errors = std.ArrayList(xml.DeleteResultEntry){};
    defer deleted.deinit(ctx.allocator);
    defer errors.deinit(ctx.allocator);

    for (keys) |k| {
        storage.deleteObject(ctx.data_dir, ctx.allocator, bucket, k) catch |e| switch (e) {
            error.ObjectNotFound => {}, // treat as success
            else => {
                errors.append(ctx.allocator, .{ .key = k, .code = "InternalError", .message = "Failed to delete" }) catch {};
                continue;
            },
        };
        deleted.append(ctx.allocator, .{ .key = k }) catch {};
    }

    const xml_body = xml.buildDeleteResult(ctx.allocator, deleted.items, errors.items, false) catch return internal(ctx, bucket);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = xml_body } };
}

// ── Multipart ────────────────────────────────────────────────────────────────

pub fn createMultipartUpload(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    const upload_id = storage.createUpload(ctx.data_dir, ctx.allocator, bucket, key, req.content_type) catch |e| return mapErr(ctx, e, key);
    const body = xml.buildInitiateMultipart(ctx.allocator, bucket, key, upload_id) catch return internal(ctx, key);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

pub fn uploadPart(ctx: HandlerContext, bucket: []const u8, _: []const u8, upload_id: []const u8, part_no: u32, req: *http.Request) http.Response {
    const etag = storage.putPart(ctx.data_dir, ctx.allocator, bucket, upload_id, part_no, req.content_length, req.body_reader) catch |e| return mapErr(ctx, e, upload_id);
    req.body_consumed = req.content_length;
    const etag_hdr = std.fmt.allocPrint(ctx.allocator, "ETag: \"{s}\"", .{etag}) catch "";
    const hdrs = ctx.allocator.dupe([]const u8, &.{etag_hdr}) catch return ok();
    return .{ .status = 200, .status_text = "OK", .extra_headers = hdrs };
}

pub fn completeMultipart(ctx: HandlerContext, bucket: []const u8, key: []const u8, upload_id: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 1024 * 1024) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Body too large", upload_id);
    const part_strs = xml.collectTagValues(ctx.allocator, body, "PartNumber") catch return internal(ctx, upload_id);
    var parts = ctx.allocator.alloc(u32, part_strs.len) catch return internal(ctx, upload_id);
    for (part_strs, 0..) |s, i| parts[i] = std.fmt.parseInt(u32, s, 10) catch 0;

    const meta = storage.completeUpload(ctx.data_dir, ctx.allocator, bucket, upload_id, parts) catch |e| return mapErr(ctx, e, upload_id);

    // In cluster mode, promote the locally-assembled object into the EC ring.
    if (ctx.cluster) |cr| {
        const opened = storage.openObject(ctx.data_dir, ctx.allocator, bucket, key) catch |e| return mapErr(ctx, e, key);
        defer opened.file.close();
        const total: usize = @intCast(opened.meta.size);
        const data = ctx.allocator.alloc(u8, total) catch return internal(ctx, key);
        defer ctx.allocator.free(data);
        const n = opened.file.readAll(data) catch return internal(ctx, key);
        if (n != total) return internal(ctx, key);

        const put_result = cr.orchestrator.put(bucket, key, data) catch |e| {
            std.log.warn("cluster multipart promote put failed: {any}", .{e});
            return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster multipart promote failed", key);
        };

        // Reuse the multipart composite ETag from local storage, NOT md5-of-body,
        // so callers see the standard `<md5>-<N>` form.
        var etag_fixed: [32]u8 = undefined;
        @memcpy(&etag_fixed, opened.meta.etag[0..@min(opened.meta.etag.len, 32)]);

        const cmeta: cluster.ObjectMeta = .{
            .shard_size = put_result.shard_size,
            .original_size = put_result.original_size,
            .etag = etag_fixed,
            .content_type = opened.meta.content_type,
            .last_modified = std.time.timestamp(),
        };
        cr.writeMeta(bucket, key, cmeta) catch |e| {
            std.log.warn("cluster multipart meta write failed: {any}", .{e});
            return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster meta write failed", key);
        };

        // Drop local copy now that it's in the cluster.
        storage.deleteObject(ctx.data_dir, ctx.allocator, bucket, key) catch {};

        if (cr.replication) |repl| {
            repl.enqueue(bucket, key, etag_fixed, cmeta.original_size, cmeta.last_modified) catch {};
        }
    }

    const location = std.fmt.allocPrint(ctx.allocator, "/{s}/{s}", .{ bucket, key }) catch "";
    const etag_quoted = std.fmt.allocPrint(ctx.allocator, "\"{s}\"", .{meta.etag}) catch "";
    const xml_body = xml.buildCompleteMultipart(ctx.allocator, location, bucket, key, etag_quoted) catch return internal(ctx, key);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = xml_body } };
}

pub fn abortMultipart(ctx: HandlerContext, bucket: []const u8, _: []const u8, upload_id: []const u8) http.Response {
    storage.abortUpload(ctx.data_dir, ctx.allocator, bucket, upload_id) catch |e| return mapErr(ctx, e, upload_id);
    return noContent();
}

pub fn listParts(ctx: HandlerContext, bucket: []const u8, key: []const u8, upload_id: []const u8) http.Response {
    const parts = storage.listParts(ctx.data_dir, ctx.allocator, bucket, upload_id) catch |e| return mapErr(ctx, e, upload_id);
    const body = xml.buildListParts(ctx.allocator, bucket, key, upload_id, parts) catch return internal(ctx, upload_id);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

// ── Health / metrics ─────────────────────────────────────────────────────────

pub fn health(_: HandlerContext) http.Response {
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = "{\"status\":\"ok\"}" } };
}

pub fn ready(ctx: HandlerContext) http.Response {
    // Test we can stat the data dir.
    var it = ctx.data_dir.iterate();
    _ = it.next() catch return .{ .status = 503, .status_text = "Service Unavailable", .content_type = "application/json", .body = .{ .bytes = "{\"status\":\"degraded\"}" } };
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = "{\"status\":\"ready\"}" } };
}

// ── Tagging / Policy / List Multipart / UploadPartCopy ──────────────────────

pub fn putObjectTagging(ctx: HandlerContext, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 64 * 1024) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Tagging body too large", key);
    storage.putObjectTagging(ctx.data_dir, ctx.allocator, bucket, key, body) catch |e| return mapErr(ctx, e, key);
    return ok();
}

pub fn getObjectTagging(ctx: HandlerContext, bucket: []const u8, key: []const u8) http.Response {
    const body = storage.getObjectTagging(ctx.data_dir, ctx.allocator, bucket, key) catch |e| return mapErr(ctx, e, key);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

pub fn deleteObjectTagging(ctx: HandlerContext, bucket: []const u8, key: []const u8) http.Response {
    storage.deleteObjectTagging(ctx.data_dir, ctx.allocator, bucket, key) catch |e| return mapErr(ctx, e, key);
    return noContent();
}

pub fn putBucketPolicy(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 256 * 1024) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Policy body too large", bucket);
    if (body.len == 0) return errResp(ctx, 400, "Bad Request", "MalformedPolicy", "Empty policy", bucket);
    // Cheap sanity check: must look like JSON object.
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') {
        return errResp(ctx, 400, "Bad Request", "MalformedPolicy", "Policy must be a JSON object", bucket);
    }
    storage.putBucketPolicy(ctx.data_dir, bucket, body) catch |e| return mapErr(ctx, e, bucket);
    return noContent();
}

pub fn getBucketPolicy(ctx: HandlerContext, bucket: []const u8) http.Response {
    const maybe = storage.getBucketPolicy(ctx.data_dir, ctx.allocator, bucket) catch |e| return mapErr(ctx, e, bucket);
    const body = maybe orelse return errResp(ctx, 404, "Not Found", "NoSuchBucketPolicy", "The bucket policy does not exist.", bucket);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/json", .body = .{ .bytes = body } };
}

pub fn deleteBucketPolicy(ctx: HandlerContext, bucket: []const u8) http.Response {
    storage.deleteBucketPolicy(ctx.data_dir, bucket) catch |e| return mapErr(ctx, e, bucket);
    return noContent();
}

pub fn putBucketLifecycle(ctx: HandlerContext, bucket: []const u8, req: *http.Request) http.Response {
    const body = req.readBodyAlloc(ctx.allocator, 256 * 1024) catch return errResp(ctx, 400, "Bad Request", "InvalidRequest", "Lifecycle body too large", bucket);
    if (body.len == 0) return errResp(ctx, 400, "Bad Request", "MalformedXML", "Empty lifecycle body", bucket);
    storage.putBucketLifecycle(ctx.data_dir, ctx.allocator, bucket, body) catch |e| switch (e) {
        error.InvalidArgument => return errResp(ctx, 400, "Bad Request", "MalformedXML", "Lifecycle XML has no rules", bucket),
        else => return mapErr(ctx, e, bucket),
    };
    return ok();
}

pub fn getBucketLifecycle(ctx: HandlerContext, bucket: []const u8) http.Response {
    const maybe = storage.getBucketLifecycle(ctx.data_dir, ctx.allocator, bucket) catch |e| return mapErr(ctx, e, bucket);
    const body = maybe orelse return errResp(ctx, 404, "Not Found", "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist.", bucket);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = body } };
}

pub fn deleteBucketLifecycle(ctx: HandlerContext, bucket: []const u8) http.Response {
    storage.deleteBucketLifecycle(ctx.data_dir, bucket) catch |e| return mapErr(ctx, e, bucket);
    return noContent();
}

pub fn listMultipartUploads(ctx: HandlerContext, bucket: []const u8) http.Response {
    const uploads = storage.listMultipartUploads(ctx.data_dir, ctx.allocator, bucket) catch |e| return mapErr(ctx, e, bucket);
    const body = xml.buildListMultipartUploads(ctx.allocator, bucket, uploads) catch return internal(ctx, bucket);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

/// UploadPartCopy: PUT /{bucket}/{key}?uploadId=&partNumber= with header
/// `x-amz-copy-source: /srcBucket/srcKey` (and optionally
/// `x-amz-copy-source-range: bytes=start-end`). Returns CopyPartResult XML.
pub fn uploadPartCopy(
    ctx: HandlerContext,
    dst_bucket: []const u8,
    upload_id: []const u8,
    part_no: u32,
    raw_src: []const u8,
    range_header: []const u8,
) http.Response {
    const src = if (raw_src.len > 0 and raw_src[0] == '/') raw_src[1..] else raw_src;
    const slash = std.mem.indexOfScalar(u8, src, '/') orelse return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad x-amz-copy-source", upload_id);
    const src_bucket = src[0..slash];
    const enc_src_key = src[slash + 1 ..];
    const src_key = util.urlDecode(ctx.allocator, enc_src_key) catch enc_src_key;

    var range: ?storage.PartCopyRange = null;
    if (range_header.len > 0) {
        const prefix = "bytes=";
        if (std.mem.startsWith(u8, range_header, prefix)) {
            const spec = range_header[prefix.len..];
            if (std.mem.indexOfScalar(u8, spec, '-')) |dash| {
                const s = std.fmt.parseInt(u64, spec[0..dash], 10) catch 0;
                const e = std.fmt.parseInt(u64, spec[dash + 1 ..], 10) catch 0;
                range = .{ .start = s, .end = e };
            }
        }
    }

    const result = storage.uploadPartCopy(ctx.data_dir, ctx.allocator, src_bucket, src_key, dst_bucket, upload_id, part_no, range) catch |e| return mapErr(ctx, e, upload_id);
    const etag_quoted = std.fmt.allocPrint(ctx.allocator, "\"{s}\"", .{result.etag}) catch return internal(ctx, upload_id);
    const body = xml.buildCopyObjectResult(ctx.allocator, result.etag, result.last_modified) catch return internal(ctx, upload_id);
    const etag_hdr = std.fmt.allocPrint(ctx.allocator, "ETag: {s}", .{etag_quoted}) catch "";
    const hdrs = ctx.allocator.dupe([]const u8, &.{etag_hdr}) catch &.{};
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body }, .extra_headers = hdrs };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ok() http.Response {
    return .{ .status = 200, .status_text = "OK" };
}

fn noContent() http.Response {
    return .{ .status = 204, .status_text = "No Content" };
}

fn internal(ctx: HandlerContext, resource: []const u8) http.Response {
    return errResp(ctx, 500, "Internal Server Error", "InternalError", "Internal error.", resource);
}

fn errResp(ctx: HandlerContext, status: u16, status_text: []const u8, code: []const u8, message: []const u8, resource: []const u8) http.Response {
    const body = xml.buildError(ctx.allocator, code, message, resource, ctx.request_id) catch "";
    return .{ .status = status, .status_text = status_text, .body = .{ .bytes = body } };
}

fn mapErr(ctx: HandlerContext, err: anyerror, resource: []const u8) http.Response {
    return switch (err) {
        error.BucketNotFound => errResp(ctx, 404, "Not Found", "NoSuchBucket", "The specified bucket does not exist.", resource),
        error.BucketAlreadyExists => errResp(ctx, 409, "Conflict", "BucketAlreadyOwnedByYou", "Bucket already exists.", resource),
        error.BucketNotEmpty => errResp(ctx, 409, "Conflict", "BucketNotEmpty", "The bucket is not empty.", resource),
        error.ObjectNotFound => errResp(ctx, 404, "Not Found", "NoSuchKey", "The specified key does not exist.", resource),
        error.UploadNotFound => errResp(ctx, 404, "Not Found", "NoSuchUpload", "The upload does not exist.", resource),
        error.InvalidKey => errResp(ctx, 400, "Bad Request", "InvalidArgument", "Invalid key or bucket name.", resource),
        error.InvalidPart => errResp(ctx, 400, "Bad Request", "InvalidPart", "Invalid part number.", resource),
        error.BadDigest => errResp(ctx, 400, "Bad Request", "BadDigest", "Content hash mismatch.", resource),
        error.OutOfMemory => errResp(ctx, 500, "Internal Server Error", "InternalError", "Out of memory.", resource),
        else => errResp(ctx, 500, "Internal Server Error", "InternalError", "Storage error.", resource),
    };
}

fn qp(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
            if (std.mem.eql(u8, param[0..eq], key)) return param[eq + 1 ..];
        } else if (std.mem.eql(u8, param, key)) {
            return "";
        }
    }
    return null;
}

const Range = struct { start: u64, end: u64 };

fn parseRange(header: []const u8, total: u64) ?Range {
    // Supports single HTTP byte ranges:
    //   bytes=start-end, bytes=start-, and suffix ranges bytes=-count.
    const prefix = "bytes=";
    if (!std.mem.startsWith(u8, header, prefix)) return null;
    if (total == 0) return null;
    const spec = header[prefix.len..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    const start_s = spec[0..dash];
    const end_s = spec[dash + 1 ..];

    if (start_s.len == 0) {
        if (end_s.len == 0) return null;
        const suffix_len = std.fmt.parseInt(u64, end_s, 10) catch return null;
        if (suffix_len == 0) return null;
        const take = @min(suffix_len, total);
        return .{ .start = total - take, .end = total - 1 };
    }

    const start = std.fmt.parseInt(u64, start_s, 10) catch return null;
    var end: u64 = total - 1;
    if (end_s.len > 0) end = std.fmt.parseInt(u64, end_s, 10) catch return null;
    if (start >= total or end >= total or start > end) return null;
    return .{ .start = start, .end = end };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "qp parses params" {
    try std.testing.expectEqualStrings("foo", qp("prefix=foo&max-keys=10", "prefix").?);
    try std.testing.expectEqualStrings("10", qp("prefix=foo&max-keys=10", "max-keys").?);
    try std.testing.expect(qp("prefix=foo", "missing") == null);
    try std.testing.expectEqualStrings("", qp("delete&other=1", "delete").?);
}

test "parseRange basic" {
    const r = parseRange("bytes=0-99", 1000).?;
    try std.testing.expectEqual(@as(u64, 0), r.start);
    try std.testing.expectEqual(@as(u64, 99), r.end);
    const r2 = parseRange("bytes=100-", 1000).?;
    try std.testing.expectEqual(@as(u64, 999), r2.end);
    const r3 = parseRange("bytes=-100", 1000).?;
    try std.testing.expectEqual(@as(u64, 900), r3.start);
    try std.testing.expectEqual(@as(u64, 999), r3.end);
    const r4 = parseRange("bytes=-2000", 1000).?;
    try std.testing.expectEqual(@as(u64, 0), r4.start);
    try std.testing.expectEqual(@as(u64, 999), r4.end);
    try std.testing.expect(parseRange("bytes=2000-3000", 1000) == null);
    try std.testing.expect(parseRange("bytes=-0", 1000) == null);
    try std.testing.expect(parseRange("bytes=0-0", 0) == null);
}

// ── Cluster-mode object handlers ─────────────────────────────────────────────
//
// In distributed mode, object data is erasure-coded across the peer set and
// metadata is replicated to the same placement group. Multipart uploads are
// assembled locally, promoted into the EC ring on CompleteMultipartUpload, and
// the local assembled copy is dropped after promotion.

fn clusterPutObject(ctx: HandlerContext, cr: *cluster.ClusterRuntime, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    if (req.header("x-amz-copy-source")) |raw_src| {
        return clusterCopyObject(ctx, cr, bucket, key, raw_src, req);
    }
    if (bucket.len < 3) return errResp(ctx, 400, "Bad Request", "InvalidBucketName", "Bucket name too short", key);

    const size: usize = @intCast(req.content_length);
    if (size > ctx.max_body_bytes) {
        return errResp(ctx, 413, "Payload Too Large", "EntityTooLarge", "Body exceeds limit", key);
    }

    // Stream directly into the encode buffer via Orchestrator.putFromReader.
    const put_result = cr.orchestrator.putFromReader(bucket, key, req.body_reader, size) catch |e| {
        std.log.warn("cluster put failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster PUT failed", key);
    };
    req.body_consumed = req.content_length;

    const etag_hex = util.hexEncodeMd5(put_result.md5);

    const meta: cluster.ObjectMeta = .{
        .shard_size = put_result.shard_size,
        .original_size = put_result.original_size,
        .etag = etag_hex,
        .content_type = req.content_type,
        .last_modified = std.time.timestamp(),
    };
    cr.writeMeta(bucket, key, meta) catch |e| {
        std.log.warn("cluster meta write failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster metadata write failed", key);
    };

    // Enqueue cross-cluster replication (best-effort; SSR worker handles delivery).
    if (cr.replication) |repl| {
        repl.enqueue(bucket, key, etag_hex, meta.original_size, meta.last_modified) catch |e| {
            std.log.warn("ssr enqueue failed: {any}", .{e});
        };
    }

    const etag_hdr = std.fmt.allocPrint(ctx.allocator, "ETag: \"{s}\"", .{etag_hex}) catch "";
    const hdrs = ctx.allocator.dupe([]const u8, &.{etag_hdr}) catch &.{};
    return .{ .status = 200, .status_text = "OK", .extra_headers = hdrs };
}

fn clusterGetObject(ctx: HandlerContext, cr: *cluster.ClusterRuntime, bucket: []const u8, key: []const u8, req: *http.Request) http.Response {
    const meta_opt = cr.readMeta(bucket, key, ctx.allocator) catch return internal(ctx, key);
    const meta = meta_opt orelse return errResp(ctx, 404, "Not Found", "NoSuchKey", "Object does not exist", key);
    defer ctx.allocator.free(meta.content_type);

    // Conditional headers (etag-based).
    if (req.header("if-none-match")) |inm| {
        const stripped = std.mem.trim(u8, inm, "\"");
        if (std.mem.eql(u8, stripped, &meta.etag)) {
            return .{ .status = 304, .status_text = "Not Modified" };
        }
    }
    if (req.header("if-match")) |im| {
        const stripped = std.mem.trim(u8, im, "\"");
        if (!std.mem.eql(u8, stripped, &meta.etag)) {
            return .{ .status = 412, .status_text = "Precondition Failed" };
        }
    }

    const data = cr.orchestrator.get(bucket, key, meta.shard_size, meta.original_size, ctx.allocator) catch |e| {
        std.log.warn("cluster get failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster GET failed", key);
    };

    var status: u16 = 200;
    var status_text: []const u8 = "OK";
    var slice = data;
    var range_hdr: ?[]const u8 = null;
    const total: u64 = meta.original_size;

    if (req.header("range")) |range| {
        if (parseRange(range, total)) |r| {
            const start: usize = @intCast(r.start);
            const end_inclusive: usize = @intCast(r.end);
            slice = data[start .. end_inclusive + 1];
            status = 206;
            status_text = "Partial Content";
            range_hdr = std.fmt.allocPrint(ctx.allocator, "Content-Range: bytes {d}-{d}/{d}", .{ r.start, r.end, total }) catch null;
        }
    }

    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
    hdrs_list.append(a, "Accept-Ranges: bytes") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, @as(i128, meta.last_modified) * std.time.ns_per_s);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
    if (range_hdr) |rh| hdrs_list.append(a, rh) catch {};
    return .{
        .status = status,
        .status_text = status_text,
        .content_type = a.dupe(u8, meta.content_type) catch "application/octet-stream",
        .body = .{ .bytes = slice },
        .extra_headers = hdrs_list.toOwnedSlice(a) catch &.{},
    };
}

fn clusterHeadObject(ctx: HandlerContext, cr: *cluster.ClusterRuntime, bucket: []const u8, key: []const u8) http.Response {
    const meta_opt = cr.readMeta(bucket, key, ctx.allocator) catch return internal(ctx, key);
    const meta = meta_opt orelse return errResp(ctx, 404, "Not Found", "NoSuchKey", "Object does not exist", key);
    defer ctx.allocator.free(meta.content_type);

    var hdrs_list = std.ArrayList([]const u8){};
    const a = ctx.allocator;
    hdrs_list.append(a, std.fmt.allocPrint(a, "ETag: \"{s}\"", .{meta.etag}) catch "") catch {};
    hdrs_list.append(a, std.fmt.allocPrint(a, "x-amz-actual-length: {d}", .{meta.original_size}) catch "") catch {};
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, @as(i128, meta.last_modified) * std.time.ns_per_s);
    hdrs_list.append(a, std.fmt.allocPrint(a, "Last-Modified: {s}", .{lm}) catch "") catch {};
    return .{
        .status = 200,
        .status_text = "OK",
        .content_type = a.dupe(u8, meta.content_type) catch "application/octet-stream",
        .extra_headers = hdrs_list.toOwnedSlice(a) catch &.{},
    };
}

fn clusterDeleteObject(ctx: HandlerContext, cr: *cluster.ClusterRuntime, bucket: []const u8, key: []const u8) http.Response {
    _ = ctx;
    cr.orchestrator.delete(bucket, key) catch {};
    cr.deleteMeta(bucket, key) catch {};
    return .{ .status = 204, .status_text = "No Content" };
}

// (clusterCopyObject sentinel)

fn clusterCopyObject(
    ctx: HandlerContext,
    cr: *cluster.ClusterRuntime,
    dst_bucket: []const u8,
    dst_key: []const u8,
    raw_src: []const u8,
    req: *http.Request,
) http.Response {
    const src = if (raw_src.len > 0 and raw_src[0] == '/') raw_src[1..] else raw_src;
    const slash = std.mem.indexOfScalar(u8, src, '/') orelse return errResp(ctx, 400, "Bad Request", "InvalidArgument", "Bad x-amz-copy-source", dst_key);
    const src_bucket = src[0..slash];
    const enc_src_key = src[slash + 1 ..];
    const src_key = util.urlDecode(ctx.allocator, enc_src_key) catch enc_src_key;

    const src_meta_opt = cr.readMeta(src_bucket, src_key, ctx.allocator) catch return internal(ctx, dst_key);
    const src_meta = src_meta_opt orelse return errResp(ctx, 404, "Not Found", "NoSuchKey", "Source object missing", src_key);
    defer ctx.allocator.free(src_meta.content_type);

    const data = cr.orchestrator.get(src_bucket, src_key, src_meta.shard_size, src_meta.original_size, ctx.allocator) catch |e| {
        std.log.warn("cluster copy GET failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster GET (copy) failed", src_key);
    };
    defer ctx.allocator.free(data);

    const put_result = cr.orchestrator.put(dst_bucket, dst_key, data) catch |e| {
        std.log.warn("cluster copy PUT failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster PUT (copy) failed", dst_key);
    };
    const etag_hex = util.hexEncodeMd5(put_result.md5);

    const dst_meta: cluster.ObjectMeta = .{
        .shard_size = put_result.shard_size,
        .original_size = put_result.original_size,
        .etag = etag_hex,
        .content_type = src_meta.content_type,
        .last_modified = std.time.timestamp(),
    };
    cr.writeMeta(dst_bucket, dst_key, dst_meta) catch |e| {
        std.log.warn("cluster copy meta write failed: {any}", .{e});
        return errResp(ctx, 500, "Internal Server Error", "InternalError", "Cluster meta write failed", dst_key);
    };

    if (cr.replication) |repl| {
        repl.enqueue(dst_bucket, dst_key, etag_hex, dst_meta.original_size, dst_meta.last_modified) catch |e| {
            std.log.warn("ssr enqueue (copy) failed: {any}", .{e});
        };
    }

    _ = req;
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, std.time.nanoTimestamp());
    const body = xml.buildCopyObjectResult(ctx.allocator, &etag_hex, lm) catch return internal(ctx, dst_key);
    return .{ .status = 200, .status_text = "OK", .content_type = "application/xml", .body = .{ .bytes = body } };
}
