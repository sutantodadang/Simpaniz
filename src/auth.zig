//! AWS Signature Version 4 verification for both header-signed
//! and presigned-URL requests. Implements only the algorithms
//! needed for S3 single-chunk PUT/GET/HEAD/DELETE/POST operations
//! using AWS4-HMAC-SHA256 with UNSIGNED-PAYLOAD or signed payloads.
const std = @import("std");
const Allocator = std.mem.Allocator;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const util = @import("util.zig");

pub const algorithm = "AWS4-HMAC-SHA256";
pub const unsigned_payload = "UNSIGNED-PAYLOAD";

pub const SignError = error{
    Unauthorized,
    SignatureMismatch,
    MalformedAuthorization,
    OutOfMemory,
    InvalidPercentEncoding,
};

pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,
};

pub const ParsedAuth = struct {
    access_key: []const u8,
    /// Date portion: YYYYMMDD.
    date_stamp: []const u8,
    region: []const u8,
    service: []const u8,
    signed_headers: []const u8,
    signature: []const u8,
};

/// Parse an `Authorization: AWS4-HMAC-SHA256 Credential=…/…, SignedHeaders=…, Signature=…` header.
/// All returned slices are subslices of `header`.
pub fn parseAuthorization(header: []const u8) SignError!ParsedAuth {
    if (!std.mem.startsWith(u8, header, algorithm)) return error.MalformedAuthorization;
    const rest = std.mem.trim(u8, header[algorithm.len..], " ");

    var ak: ?[]const u8 = null;
    var dt: ?[]const u8 = null;
    var rg: ?[]const u8 = null;
    var sv: ?[]const u8 = null;
    var sh: ?[]const u8 = null;
    var sig: ?[]const u8 = null;

    var iter = std.mem.splitScalar(u8, rest, ',');
    while (iter.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " ");
        if (std.mem.startsWith(u8, part, "Credential=")) {
            const v = part["Credential=".len..];
            // ak/date/region/service/aws4_request
            var c = std.mem.splitScalar(u8, v, '/');
            ak = c.next() orelse return error.MalformedAuthorization;
            dt = c.next() orelse return error.MalformedAuthorization;
            rg = c.next() orelse return error.MalformedAuthorization;
            sv = c.next() orelse return error.MalformedAuthorization;
            const tail = c.next() orelse return error.MalformedAuthorization;
            if (!std.mem.eql(u8, tail, "aws4_request")) return error.MalformedAuthorization;
        } else if (std.mem.startsWith(u8, part, "SignedHeaders=")) {
            sh = part["SignedHeaders=".len..];
        } else if (std.mem.startsWith(u8, part, "Signature=")) {
            sig = part["Signature=".len..];
        }
    }
    return .{
        .access_key = ak orelse return error.MalformedAuthorization,
        .date_stamp = dt orelse return error.MalformedAuthorization,
        .region = rg orelse return error.MalformedAuthorization,
        .service = sv orelse return error.MalformedAuthorization,
        .signed_headers = sh orelse return error.MalformedAuthorization,
        .signature = sig orelse return error.MalformedAuthorization,
    };
}

// ── Low-level primitives ─────────────────────────────────────────────────────

/// Compute the SigV4 derived signing key for a date/region/service.
pub fn deriveSigningKey(secret: []const u8, date_stamp: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var k_secret_buf: [128]u8 = undefined;
    const k_secret = std.fmt.bufPrint(&k_secret_buf, "AWS4{s}", .{secret}) catch unreachable;

    var k_date: [32]u8 = undefined;
    HmacSha256.create(&k_date, date_stamp, k_secret);
    var k_region: [32]u8 = undefined;
    HmacSha256.create(&k_region, region, &k_date);
    var k_service: [32]u8 = undefined;
    HmacSha256.create(&k_service, service, &k_region);
    var k_signing: [32]u8 = undefined;
    HmacSha256.create(&k_signing, "aws4_request", &k_service);
    return k_signing;
}

pub fn sha256Hex(data: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(data, &d, .{});
    return util.hexEncodeSha256(d);
}

// ── Canonical request ────────────────────────────────────────────────────────

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Build the SigV4 canonical request string for the given inputs.
/// `signed_headers` is the lowercase semicolon list as per the Authorization header.
/// `headers` is the full set of request headers (caller-owned). Only the ones
/// listed in `signed_headers` are included in the canonical form.
pub fn buildCanonicalRequest(
    allocator: Allocator,
    method: []const u8,
    canonical_uri: []const u8,
    canonical_query: []const u8,
    headers: []const Header,
    signed_headers: []const u8,
    payload_hash: []const u8,
) Allocator.Error![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, method);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, canonical_uri);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, canonical_query);
    try out.append(allocator, '\n');

    // Iterate signed headers in order; emit "name:trimmed-value\n".
    var iter = std.mem.splitScalar(u8, signed_headers, ';');
    while (iter.next()) |hname| {
        try out.appendSlice(allocator, hname);
        try out.append(allocator, ':');
        const value = findHeader(headers, hname) orelse "";
        try out.appendSlice(allocator, std.mem.trim(u8, value, " \t"));
        try out.append(allocator, '\n');
    }
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, signed_headers);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, payload_hash);
    return out.toOwnedSlice(allocator);
}

fn findHeader(headers: []const Header, name_lower: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name_lower)) return h.value;
    }
    return null;
}

/// Build the SigV4 string-to-sign.
pub fn buildStringToSign(
    allocator: Allocator,
    amz_date: []const u8,
    date_stamp: []const u8,
    region: []const u8,
    service: []const u8,
    canonical_request: []const u8,
) Allocator.Error![]u8 {
    const cr_hash = sha256Hex(canonical_request);
    return std.fmt.allocPrint(
        allocator,
        "{s}\n{s}\n{s}/{s}/{s}/aws4_request\n{s}",
        .{ algorithm, amz_date, date_stamp, region, service, &cr_hash },
    );
}

/// Compute the final SigV4 hex signature.
pub fn computeSignature(
    secret: []const u8,
    date_stamp: []const u8,
    region: []const u8,
    service: []const u8,
    string_to_sign: []const u8,
) [64]u8 {
    const key = deriveSigningKey(secret, date_stamp, region, service);
    var sig: [32]u8 = undefined;
    HmacSha256.create(&sig, string_to_sign, &key);
    return util.hexEncodeSha256(sig);
}

// ── High-level verification ──────────────────────────────────────────────────

pub const VerifyInput = struct {
    method: []const u8,
    /// Canonical URI: starts with '/', already URI-encoded but not double-encoded.
    /// For S3 we use the raw path (single encoding pass).
    canonical_uri: []const u8,
    /// Pre-built canonical query string (sorted, encoded).
    canonical_query: []const u8,
    headers: []const Header,
    /// Either the hex SHA-256 of the body, or "UNSIGNED-PAYLOAD".
    payload_hash: []const u8,
    /// Authorization header value (without leading "Authorization: ").
    authorization: []const u8,
    /// x-amz-date header value (e.g., 20240101T120000Z).
    amz_date: []const u8,
};

/// Verify a SigV4 header-signed request against the configured credentials.
/// Returns true on match. Uses constant-time comparison.
pub fn verifyHeaderSignedRequest(
    allocator: Allocator,
    creds: Credentials,
    input: VerifyInput,
) SignError!void {
    const auth = try parseAuthorization(input.authorization);
    if (!std.mem.eql(u8, auth.access_key, creds.access_key)) return error.Unauthorized;

    const cr = buildCanonicalRequest(
        allocator,
        input.method,
        input.canonical_uri,
        input.canonical_query,
        input.headers,
        auth.signed_headers,
        input.payload_hash,
    ) catch return error.OutOfMemory;
    defer allocator.free(cr);

    const sts = buildStringToSign(
        allocator,
        input.amz_date,
        auth.date_stamp,
        auth.region,
        auth.service,
        cr,
    ) catch return error.OutOfMemory;
    defer allocator.free(sts);

    const expected = computeSignature(
        creds.secret_key,
        auth.date_stamp,
        auth.region,
        auth.service,
        sts,
    );

    if (auth.signature.len != expected.len) return error.SignatureMismatch;
    if (!std.crypto.timing_safe.eql([64]u8, expected, auth.signature[0..64].*)) {
        return error.SignatureMismatch;
    }
}

/// Build the canonical query string for a presigned URL by removing
/// `X-Amz-Signature` and re-sorting key=value pairs.
pub fn canonicalizePresignedQuery(
    allocator: Allocator,
    raw_query: []const u8,
) Allocator.Error![]u8 {
    var pairs = std.ArrayList(struct { k: []u8, v: []u8 }){};
    defer {
        for (pairs.items) |p| {
            allocator.free(p.k);
            allocator.free(p.v);
        }
        pairs.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, raw_query, '&');
    while (iter.next()) |part| {
        if (part.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const k_raw = part[0..eq];
        const v_raw = part[eq + 1 ..];
        if (std.mem.eql(u8, k_raw, "X-Amz-Signature")) continue;

        const k_dec = util.urlDecode(allocator, k_raw) catch continue;
        defer allocator.free(k_dec);
        const v_dec = util.urlDecode(allocator, v_raw) catch continue;
        defer allocator.free(v_dec);

        const k_enc = try util.awsUriEncode(allocator, k_dec, true);
        const v_enc = try util.awsUriEncode(allocator, v_dec, true);
        try pairs.append(allocator, .{ .k = k_enc, .v = v_enc });
    }

    std.mem.sort(@TypeOf(pairs.items[0]), pairs.items, {}, struct {
        fn lt(_: void, a: @TypeOf(pairs.items[0]), b: @TypeOf(pairs.items[0])) bool {
            return std.mem.lessThan(u8, a.k, b.k);
        }
    }.lt);

    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);
    for (pairs.items, 0..) |p, i| {
        if (i > 0) try out.append(allocator, '&');
        try out.appendSlice(allocator, p.k);
        try out.append(allocator, '=');
        try out.appendSlice(allocator, p.v);
    }
    return out.toOwnedSlice(allocator);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "parseAuthorization basic" {
    const h = "AWS4-HMAC-SHA256 Credential=AKIA/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef";
    const a = try parseAuthorization(h);
    try std.testing.expectEqualStrings("AKIA", a.access_key);
    try std.testing.expectEqualStrings("20240101", a.date_stamp);
    try std.testing.expectEqualStrings("us-east-1", a.region);
    try std.testing.expectEqualStrings("s3", a.service);
    try std.testing.expectEqualStrings("host;x-amz-date", a.signed_headers);
    try std.testing.expectEqualStrings("abcdef", a.signature);
}

test "deriveSigningKey known vector" {
    // Test vector from AWS docs:
    // secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY date=20120215 region=us-east-1 service=iam
    const k = deriveSigningKey(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20120215",
        "us-east-1",
        "iam",
    );
    const hex = util.hexEncodeSha256(k);
    try std.testing.expectEqualStrings(
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
        &hex,
    );
}

test "verifyHeaderSignedRequest roundtrip" {
    const a = std.testing.allocator;
    const creds = Credentials{
        .access_key = "AKIDEXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
    };
    const headers = [_]Header{
        .{ .name = "host", .value = "examplebucket.s3.amazonaws.com" },
        .{ .name = "x-amz-content-sha256", .value = unsigned_payload },
        .{ .name = "x-amz-date", .value = "20130524T000000Z" },
    };
    const cr = try buildCanonicalRequest(a, "GET", "/test.txt", "", &headers, "host;x-amz-content-sha256;x-amz-date", unsigned_payload);
    defer a.free(cr);
    const sts = try buildStringToSign(a, "20130524T000000Z", "20130524", "us-east-1", "s3", cr);
    defer a.free(sts);
    const expected = computeSignature(creds.secret_key, "20130524", "us-east-1", "s3", sts);

    var auth_buf: [512]u8 = undefined;
    const auth_value = try std.fmt.bufPrint(&auth_buf, "{s} Credential={s}/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={s}", .{ algorithm, creds.access_key, &expected });

    try verifyHeaderSignedRequest(a, creds, .{
        .method = "GET",
        .canonical_uri = "/test.txt",
        .canonical_query = "",
        .headers = &headers,
        .payload_hash = unsigned_payload,
        .authorization = auth_value,
        .amz_date = "20130524T000000Z",
    });
}

test "verifyHeaderSignedRequest tampered signature" {
    const a = std.testing.allocator;
    const creds = Credentials{ .access_key = "AKIDEXAMPLE", .secret_key = "secret", .region = "us-east-1" };
    const headers = [_]Header{
        .{ .name = "host", .value = "h" },
        .{ .name = "x-amz-date", .value = "20240101T000000Z" },
    };
    const bogus = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" ++ ("0" ** 64);
    try std.testing.expectError(error.SignatureMismatch, verifyHeaderSignedRequest(a, creds, .{
        .method = "GET",
        .canonical_uri = "/",
        .canonical_query = "",
        .headers = &headers,
        .payload_hash = unsigned_payload,
        .authorization = bogus,
        .amz_date = "20240101T000000Z",
    }));
}

test "canonicalizePresignedQuery sorts and drops signature" {
    const a = std.testing.allocator;
    const out = try canonicalizePresignedQuery(a, "X-Amz-Signature=abc&Z=1&A=2&M=3");
    defer a.free(out);
    try std.testing.expectEqualStrings("A=2&M=3&Z=1", out);
}
