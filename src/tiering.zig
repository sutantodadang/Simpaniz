//! Cold storage tiering for lifecycle Transition rules.
//!
//! Two target modes, selected at startup from environment variables:
//!   - local:  `SIMPANIZ_TIER_DIR=<path>` — a second on-disk root; objects
//!             are copied there verbatim (whatever bytes are on disk locally
//!             — plaintext or SSE ciphertext, unchanged).
//!   - remote: `SIMPANIZ_TIER_URL` + `SIMPANIZ_TIER_BUCKET` +
//!             `SIMPANIZ_TIER_ACCESS_KEY` + `SIMPANIZ_TIER_SECRET_KEY`
//!             (+ optional `SIMPANIZ_TIER_REGION`, default us-east-1) — a
//!             SigV4-signed PUT/GET against another S3-compatible endpoint
//!             (this server, or a real one), under
//!             `<url>/<tier_bucket>/<src_bucket>/<key>`.
//!
//! `transitionObject` moves the on-disk bytes to the cold target, then
//! replaces the local file with a zero-byte stub and marks the metadata
//! sidecar `tiered = true` / `storage_class = <class>`. Reads are
//! transparent: `fetchCold` returns the original bytes, and callers (GET/
//! HEAD in handlers.zig) spool them to a temp file so the existing
//! file-based body/range/decrypt machinery keeps working unchanged.
//!
//! ponytail: no rehydration policy yet — GET always re-fetches from cold on
//! every request rather than restoring the object locally.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const auth = @import("auth.zig");
const internal = @import("storage/internal.zig");
const s3_client = @import("s3_client.zig");

pub const Mode = enum { off, local, remote };

pub const Tiering = struct {
    mode: Mode = .off,

    // local mode
    tier_root: ?Dir = null,

    // remote mode
    url: []const u8 = "",
    tier_bucket: []const u8 = "",
    access_key: []const u8 = "",
    secret_key: []const u8 = "",
    region: []const u8 = "us-east-1",

    /// Build from environment variables. Process-lifetime config (like
    /// config.zig), never deinit'd — matches existing daemon-context patterns.
    pub fn init(allocator: Allocator) Tiering {
        if (std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_DIR") catch null) |tier_dir| {
            const dir = openOrCreateDir(tier_dir) catch |e| {
                std.log.err("tiering: failed to open SIMPANIZ_TIER_DIR={s}: {}", .{ tier_dir, e });
                return .{};
            };
            return .{ .mode = .local, .tier_root = dir };
        }

        if (std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_URL") catch null) |url| {
            const tier_bucket = std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_BUCKET") catch (allocator.dupe(u8, "") catch "");
            const access_key = std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_ACCESS_KEY") catch (allocator.dupe(u8, "") catch "");
            const secret_key = std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_SECRET_KEY") catch (allocator.dupe(u8, "") catch "");
            const region = std.process.getEnvVarOwned(allocator, "SIMPANIZ_TIER_REGION") catch (allocator.dupe(u8, "us-east-1") catch "us-east-1");
            return .{
                .mode = .remote,
                .url = url,
                .tier_bucket = tier_bucket,
                .access_key = access_key,
                .secret_key = secret_key,
                .region = region,
            };
        }

        return .{};
    }

    /// Move `key`'s on-disk bytes (in bucket dir `bd`) to the cold target,
    /// then stub the local file and mark it tiered in the metadata sidecar.
    /// Idempotent-by-caller: callers should check `meta.tiered` first.
    pub fn transitionObject(
        self: *Tiering,
        bd: Dir,
        allocator: Allocator,
        bucket: []const u8,
        key: []const u8,
        storage_class: []const u8,
    ) !void {
        if (self.mode == .off) return error.TieringNotConfigured;

        const data = blk: {
            var f = try bd.openFile(key, .{});
            defer f.close();
            const stat = try f.stat();
            const buf = try allocator.alloc(u8, @intCast(stat.size));
            errdefer allocator.free(buf);
            _ = try f.readAll(buf);
            break :blk buf;
        };
        defer allocator.free(data);

        switch (self.mode) {
            .local => try self.uploadLocal(bucket, key, data),
            .remote => try self.uploadRemote(allocator, bucket, key, data),
            .off => unreachable,
        }

        var meta = try internal.readMetadata(bd, allocator, key);
        defer allocator.free(meta.content_type);
        defer allocator.free(meta.etag);
        defer if (meta.encryption) |enc| {
            allocator.free(enc.alg);
            allocator.free(enc.wrapped_dek_b64);
            allocator.free(enc.wrap_nonce_b64);
            allocator.free(enc.sse_c_key_md5);
            allocator.free(enc.kms_key_id);
        };
        // The sidecar's previous storage_class (if any) is about to be
        // replaced by the caller-supplied (borrowed, not owned) value below
        // — free the old allocation now rather than via a deferred free
        // that would otherwise see the overwritten (non-owned) value.
        allocator.free(meta.storage_class);
        meta.storage_class = storage_class;
        meta.tiered = true;

        {
            var tf = try bd.createFile(key, .{ .truncate = true });
            tf.close();
        }

        try internal.writeMetadata(bd, allocator, key, meta);
    }

    /// Fetch the original bytes for a tiered object. Caller frees.
    pub fn fetchCold(self: *Tiering, allocator: Allocator, bucket: []const u8, key: []const u8) ![]u8 {
        return switch (self.mode) {
            .off => error.TieringNotConfigured,
            .local => blk: {
                var root = self.tier_root orelse return error.TieringNotConfigured;
                var bd = root.openDir(bucket, .{}) catch return error.ColdObjectNotFound;
                defer bd.close();
                var f = bd.openFile(key, .{}) catch return error.ColdObjectNotFound;
                defer f.close();
                const stat = try f.stat();
                const buf = try allocator.alloc(u8, @intCast(stat.size));
                errdefer allocator.free(buf);
                _ = try f.readAll(buf);
                break :blk buf;
            },
            .remote => try self.fetchRemote(allocator, bucket, key),
        };
    }

    fn uploadLocal(self: *Tiering, bucket: []const u8, key: []const u8, data: []const u8) !void {
        var root = self.tier_root orelse return error.TieringNotConfigured;
        var bd = root.makeOpenPath(bucket, .{}) catch return error.Internal;
        defer bd.close();
        if (std.fs.path.dirname(key)) |parent| bd.makePath(parent) catch {};
        bd.writeFile(.{ .sub_path = key, .data = data }) catch return error.Internal;
    }

    fn uploadRemote(self: *Tiering, allocator: Allocator, bucket: []const u8, key: []const u8, data: []const u8) !void {
        const url = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}/{s}", .{ self.url, self.tier_bucket, bucket, key });
        defer allocator.free(url);

        const payload_hash_arr = auth.sha256Hex(data);
        var amz_date_buf: [16]u8 = undefined;
        const now = std.time.nanoTimestamp();
        const amz_date = s3_client.fmtAmzDate(&amz_date_buf, now);
        const date_stamp = amz_date[0..8];

        const uri = try self.pathOnly(allocator, bucket, key);
        defer allocator.free(uri);
        const host = try self.hostOnly(allocator);
        defer allocator.free(host);

        const auth_header = try s3_client.signRequest(allocator, self.credentials(), "PUT", uri, host, &payload_hash_arr, amz_date, date_stamp);
        defer allocator.free(auth_header);

        var hdrs = std.ArrayList(std.http.Header){};
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = "x-amz-content-sha256", .value = &payload_hash_arr });
        try hdrs.append(allocator, .{ .name = "x-amz-date", .value = amz_date });
        try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_header });

        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .PUT,
            .payload = data,
            .headers = .{ .content_type = .{ .override = "application/octet-stream" } },
            .extra_headers = hdrs.items,
            .keep_alive = false,
        }) catch return error.UploadFailed;

        const code = @intFromEnum(result.status);
        if (code < 200 or code >= 300) return error.UploadRejected;
    }

    fn fetchRemote(self: *Tiering, allocator: Allocator, bucket: []const u8, key: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}/{s}", .{ self.url, self.tier_bucket, bucket, key });
        defer allocator.free(url);

        var amz_date_buf: [16]u8 = undefined;
        const now = std.time.nanoTimestamp();
        const amz_date = s3_client.fmtAmzDate(&amz_date_buf, now);
        const date_stamp = amz_date[0..8];

        const uri = try self.pathOnly(allocator, bucket, key);
        defer allocator.free(uri);
        const host = try self.hostOnly(allocator);
        defer allocator.free(host);

        const auth_header = try s3_client.signRequest(allocator, self.credentials(), "GET", uri, host, auth.unsigned_payload, amz_date, date_stamp);
        defer allocator.free(auth_header);

        var hdrs = std.ArrayList(std.http.Header){};
        defer hdrs.deinit(allocator);
        try hdrs.append(allocator, .{ .name = "x-amz-content-sha256", .value = auth.unsigned_payload });
        try hdrs.append(allocator, .{ .name = "x-amz-date", .value = amz_date });
        try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_header });

        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();

        var body = std.Io.Writer.Allocating.init(allocator);
        errdefer body.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .extra_headers = hdrs.items,
            .keep_alive = false,
            .response_writer = &body.writer,
        }) catch return error.FetchFailed;

        const code = @intFromEnum(result.status);
        if (code < 200 or code >= 300) {
            body.deinit();
            return error.ColdObjectNotFound;
        }
        return body.toOwnedSlice();
    }

    fn credentials(self: *const Tiering) auth.Credentials {
        return .{ .access_key = self.access_key, .secret_key = self.secret_key, .region = self.region };
    }

    fn pathOnly(self: *const Tiering, allocator: Allocator, bucket: []const u8, key: []const u8) ![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "/{s}/{s}", .{ bucket, key });
    }

    fn hostOnly(self: *const Tiering, allocator: Allocator) ![]u8 {
        const uri = std.Uri.parse(self.url) catch return allocator.dupe(u8, "");
        const host_comp = uri.host orelse return allocator.dupe(u8, "");
        return allocator.dupe(u8, host_comp.percent_encoded);
    }
};

fn freeObjectMeta(allocator: Allocator, meta: anytype) void {
    allocator.free(meta.content_type);
    allocator.free(meta.etag);
    allocator.free(meta.storage_class);
    if (meta.encryption) |enc| {
        allocator.free(enc.alg);
        allocator.free(enc.wrapped_dek_b64);
        allocator.free(enc.wrap_nonce_b64);
        allocator.free(enc.sse_c_key_md5);
        allocator.free(enc.kms_key_id);
    }
}

fn openOrCreateDir(path: []const u8) !Dir {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.makeDirAbsolute(path) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
        return std.fs.openDirAbsolute(path, .{});
    }
    try std.fs.cwd().makePath(path);
    return std.fs.cwd().openDir(path, .{});
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "local tiering: transitionObject stubs local file, cold copy has original bytes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var cold_tmp = std.testing.tmpDir(.{ .iterate = true });
    defer cold_tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    const objects = @import("storage/objects.zig");
    try buckets.createBucket(tmp.dir, "tier-bucket");

    var fbs = std.Io.Reader.fixed("cold me down");
    const put_meta = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "tier-bucket",
        .key = "big.bin",
        .content_length = 12,
        .content_type = "text/plain",
    }, &fbs);
    allocator.free(put_meta.content_type);
    allocator.free(put_meta.etag);

    var bd = try tmp.dir.openDir("tier-bucket", .{});
    defer bd.close();

    var tiering: Tiering = .{ .mode = .local, .tier_root = cold_tmp.dir };
    try tiering.transitionObject(bd, allocator, "tier-bucket", "big.bin", "COLD");

    // Local file is now a zero-byte stub.
    const local_stat = try bd.statFile("big.bin");
    try std.testing.expectEqual(@as(u64, 0), local_stat.size);

    // Metadata reflects the tiered state, but reports the original size.
    const meta = try internal.readMetadata(bd, allocator, "big.bin");
    defer freeObjectMeta(allocator, meta);
    try std.testing.expect(meta.tiered);
    try std.testing.expectEqualStrings("COLD", meta.storage_class);
    try std.testing.expectEqual(@as(u64, 12), meta.size);

    // Cold copy holds the original bytes.
    const cold_bytes = try tiering.fetchCold(allocator, "tier-bucket", "big.bin");
    defer allocator.free(cold_bytes);
    try std.testing.expectEqualStrings("cold me down", cold_bytes);
}

test "signRequest is deterministic and produces a well-formed Authorization header" {
    const allocator = std.testing.allocator;
    const creds = auth.Credentials{ .access_key = "AKIDEXAMPLE", .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", .region = "us-east-1" };
    const payload_hash = auth.sha256Hex("hello cold tier");

    const h1 = try s3_client.signRequest(allocator, creds, "PUT", "/coldbucket/srcbucket/key.bin", "cold.example.com", &payload_hash, "20240101T000000Z", "20240101");
    defer allocator.free(h1);
    const h2 = try s3_client.signRequest(allocator, creds, "PUT", "/coldbucket/srcbucket/key.bin", "cold.example.com", &payload_hash, "20240101T000000Z", "20240101");
    defer allocator.free(h2);

    try std.testing.expectEqualStrings(h1, h2);
    try std.testing.expect(std.mem.startsWith(u8, h1, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="));

    const sig_start = std.mem.indexOf(u8, h1, "Signature=").? + "Signature=".len;
    const sig = h1[sig_start..];
    try std.testing.expectEqual(@as(usize, 64), sig.len);
    for (sig) |c| try std.testing.expect(std.ascii.isHex(c));
}
