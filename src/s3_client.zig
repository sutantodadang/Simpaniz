//! Minimal SigV4-signed HTTP client helpers, shared by cold-tier uploads
//! (`tiering.zig`) and the `simpaniz admin` CLI (`admin_cli.zig`).
//!
//! `signRequest`/`fmtAmzDate` were extracted verbatim from `tiering.zig`
//! (same signature, same body) — that module still owns its own
//! streaming upload/fetch request plumbing (different payload/error
//! handling needs), it just calls these shared primitives instead of
//! defining its own copies.
//!
//! `request` is new: a small end-to-end "sign, send, collect body" helper
//! for simple JSON/bytes calls against an S3-compatible endpoint. Used by
//! `admin_cli.zig` to talk to this server's `/_admin/*` REST API.
const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const util = @import("util.zig");

pub const Credentials = auth.Credentials;

/// Format an x-amz-date value (YYYYMMDDTHHMMSSZ) from a nanosecond
/// timestamp.
pub fn fmtAmzDate(buf: *[16]u8, ns_since_epoch: i128) []const u8 {
    return util.formatAmzDate(buf, ns_since_epoch);
}

/// Build a SigV4 Authorization header value for a request signing exactly
/// `host`, `x-amz-content-sha256`, and `x-amz-date` (no query string, no
/// other signed headers). Deterministic given inputs.
pub fn signRequest(
    allocator: Allocator,
    creds: Credentials,
    method: []const u8,
    uri: []const u8,
    host: []const u8,
    payload_hash: []const u8,
    amz_date: []const u8,
    date_stamp: []const u8,
) ![]u8 {
    const signed_headers = "host;x-amz-content-sha256;x-amz-date";
    const headers = [_]auth.Header{
        .{ .name = "host", .value = host },
        .{ .name = "x-amz-content-sha256", .value = payload_hash },
        .{ .name = "x-amz-date", .value = amz_date },
    };
    const cr = try auth.buildCanonicalRequest(allocator, method, uri, "", &headers, signed_headers, payload_hash);
    defer allocator.free(cr);
    const sts = try auth.buildStringToSign(allocator, amz_date, date_stamp, creds.region, "s3", cr);
    defer allocator.free(sts);
    const sig = auth.computeSignature(creds.secret_key, date_stamp, creds.region, "s3", sts);
    return std.fmt.allocPrint(
        allocator,
        "{s} Credential={s}/{s}/{s}/s3/aws4_request, SignedHeaders={s}, Signature={s}",
        .{ auth.algorithm, creds.access_key, date_stamp, creds.region, signed_headers, &sig },
    );
}

pub const Response = struct {
    status: u16,
    body: []u8,
};

/// Extract "host" or "host:port" from a URL, for use as both the signed
/// `host` header and the actual outgoing `Host` header (see `request`
/// below, which overrides the Host header explicitly with this value —
/// that guarantees the two always match, regardless of what
/// `std.http.Client` would otherwise default it to for non-standard
/// ports).
pub fn hostFromUrl(allocator: Allocator, url: []const u8) ![]u8 {
    const uri = try std.Uri.parse(url);
    const host_comp = uri.host orelse return error.InvalidUrl;
    if (uri.port) |port| {
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_comp.percent_encoded, port });
    }
    return allocator.dupe(u8, host_comp.percent_encoded);
}

/// Issue a single SigV4-signed HTTP request against `endpoint + path`
/// (`endpoint` like "http://127.0.0.1:9000", `path` like
/// "/_admin/users/foo", already the exact bytes to sign — no extra
/// URI-encoding is applied). Optional `body` is signed and sent as-is; the
/// caller owns freeing `Response.body`.
pub fn request(
    allocator: Allocator,
    creds: Credentials,
    endpoint: []const u8,
    method: std.http.Method,
    path: []const u8,
    body: ?[]const u8,
) !Response {
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ endpoint, path });
    defer allocator.free(url);

    const payload_hash_arr = auth.sha256Hex(body orelse "");
    var amz_date_buf: [16]u8 = undefined;
    const now = std.time.nanoTimestamp();
    const amz_date = fmtAmzDate(&amz_date_buf, now);
    const date_stamp = amz_date[0..8];

    const host = try hostFromUrl(allocator, endpoint);
    defer allocator.free(host);

    const method_name = @tagName(method);

    const auth_header = try signRequest(allocator, creds, method_name, path, host, &payload_hash_arr, amz_date, date_stamp);
    defer allocator.free(auth_header);

    var hdrs = std.ArrayList(std.http.Header){};
    defer hdrs.deinit(allocator);
    try hdrs.append(allocator, .{ .name = "x-amz-content-sha256", .value = &payload_hash_arr });
    try hdrs.append(allocator, .{ .name = "x-amz-date", .value = amz_date });
    try hdrs.append(allocator, .{ .name = "Authorization", .value = auth_header });

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var resp_body = std.Io.Writer.Allocating.init(allocator);
    errdefer resp_body.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = body,
        .headers = .{
            .host = .{ .override = host },
            .content_type = .{ .override = "application/json" },
        },
        .extra_headers = hdrs.items,
        .keep_alive = false,
        .response_writer = &resp_body.writer,
    }) catch return error.RequestFailed;

    return .{ .status = @intFromEnum(result.status), .body = try resp_body.toOwnedSlice() };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "hostFromUrl includes non-default port" {
    const a = std.testing.allocator;
    const h = try hostFromUrl(a, "http://127.0.0.1:9000");
    defer a.free(h);
    try std.testing.expectEqualStrings("127.0.0.1:9000", h);
}

test "hostFromUrl omits absent port" {
    const a = std.testing.allocator;
    const h = try hostFromUrl(a, "http://example.com");
    defer a.free(h);
    try std.testing.expectEqualStrings("example.com", h);
}

test "signRequest is deterministic for identical inputs" {
    const a = std.testing.allocator;
    const creds = Credentials{ .access_key = "AK", .secret_key = "SK", .region = "us-east-1" };
    const h1 = try signRequest(a, creds, "GET", "/_admin/info", "127.0.0.1:9000", "UNSIGNED-PAYLOAD", "20240101T000000Z", "20240101");
    defer a.free(h1);
    const h2 = try signRequest(a, creds, "GET", "/_admin/info", "127.0.0.1:9000", "UNSIGNED-PAYLOAD", "20240101T000000Z", "20240101");
    defer a.free(h2);
    try std.testing.expectEqualStrings(h1, h2);
}
