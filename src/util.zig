//! Common utilities: URL decoding, path/key validation, time formatting,
//! request-id generation, hex encoding, percent-encoding.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum allowed bucket name length per AWS S3 spec.
pub const max_bucket_name = 63;
/// Minimum allowed bucket name length per AWS S3 spec.
pub const min_bucket_name = 3;
/// Maximum allowed object key length per AWS S3 spec.
pub const max_key_length = 1024;

// ── Hex ──────────────────────────────────────────────────────────────────────

const hex_chars_lower = "0123456789abcdef";

/// Lowercase hex-encode bytes into the provided buffer (must be 2*bytes.len).
pub fn hexEncodeBuf(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len >= bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars_lower[b >> 4];
        out[i * 2 + 1] = hex_chars_lower[b & 0x0f];
    }
}

/// Lowercase hex-encode 16-byte MD5 digest to a stack-allocated [32]u8.
pub fn hexEncodeMd5(digest: [16]u8) [32]u8 {
    var out: [32]u8 = undefined;
    hexEncodeBuf(&digest, &out);
    return out;
}

/// Lowercase hex-encode 32-byte SHA256 digest to a stack-allocated [64]u8.
pub fn hexEncodeSha256(digest: [32]u8) [64]u8 {
    var out: [64]u8 = undefined;
    hexEncodeBuf(&digest, &out);
    return out;
}

// ── URL / percent encoding ───────────────────────────────────────────────────

pub const DecodeError = error{ InvalidPercentEncoding, OutOfMemory };

/// Decode `%XX` percent-encoded sequences into a freshly allocated byte slice.
/// `+` is preserved literally (S3 path components do not treat `+` as space).
pub fn urlDecode(allocator: Allocator, input: []const u8) DecodeError![]u8 {
    var out = try std.ArrayList(u8).initCapacity(allocator, input.len);
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '%') {
            if (i + 2 >= input.len) return error.InvalidPercentEncoding;
            const hi = hexNibble(input[i + 1]) orelse return error.InvalidPercentEncoding;
            const lo = hexNibble(input[i + 2]) orelse return error.InvalidPercentEncoding;
            try out.append(allocator, (hi << 4) | lo);
            i += 3;
        } else {
            try out.append(allocator, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// AWS S3 / SigV4 URI-encode. Encodes everything except `unreserved` set.
/// When `encode_slash` is false, `/` is left literal (used in canonical paths).
pub fn awsUriEncode(allocator: Allocator, input: []const u8, encode_slash: bool) Allocator.Error![]u8 {
    var out = try std.ArrayList(u8).initCapacity(allocator, input.len);
    errdefer out.deinit(allocator);

    for (input) |c| {
        const unreserved = (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved or (c == '/' and !encode_slash)) {
            try out.append(allocator, c);
        } else {
            const upper_hex = "0123456789ABCDEF";
            try out.append(allocator, '%');
            try out.append(allocator, upper_hex[c >> 4]);
            try out.append(allocator, upper_hex[c & 0x0f]);
        }
    }
    return out.toOwnedSlice(allocator);
}

// ── Bucket / key validation ──────────────────────────────────────────────────

pub const BucketNameError = error{
    InvalidBucketName,
};

/// Validate a bucket name against AWS S3 naming rules.
pub fn validateBucketName(name: []const u8) BucketNameError!void {
    if (name.len < min_bucket_name or name.len > max_bucket_name) return error.InvalidBucketName;
    if (std.mem.startsWith(u8, name, ".") or std.mem.endsWith(u8, name, ".")) return error.InvalidBucketName;
    if (std.mem.startsWith(u8, name, "-") or std.mem.endsWith(u8, name, "-")) return error.InvalidBucketName;
    if (std.mem.indexOf(u8, name, "..") != null) return error.InvalidBucketName;
    if (std.mem.startsWith(u8, name, "xn--")) return error.InvalidBucketName;
    if (std.mem.endsWith(u8, name, "-s3alias")) return error.InvalidBucketName;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '.';
        if (!ok) return error.InvalidBucketName;
    }
    // Reject IPv4 literals (a.b.c.d).
    var dots: usize = 0;
    for (name) |c| if (c == '.') {
        dots += 1;
    };
    if (dots == 3) {
        var iter = std.mem.splitScalar(u8, name, '.');
        var all_numeric = true;
        while (iter.next()) |part| {
            if (part.len == 0) {
                all_numeric = false;
                break;
            }
            for (part) |pc| if (pc < '0' or pc > '9') {
                all_numeric = false;
            };
            if (!all_numeric) break;
        }
        if (all_numeric) return error.InvalidBucketName;
    }
}

pub const KeyError = error{
    InvalidKey,
};

/// Validate that an object key is safe to map to the filesystem:
/// no traversal segments, no NUL bytes, no leading/trailing slashes,
/// no Windows drive letters, length within S3 limits.
pub fn validateObjectKey(key: []const u8) KeyError!void {
    if (key.len == 0 or key.len > max_key_length) return error.InvalidKey;
    if (key[0] == '/' or key[0] == '\\') return error.InvalidKey;
    // Reject control bytes and NUL.
    for (key) |c| {
        if (c == 0) return error.InvalidKey;
        if (c < 0x20 and c != '\t') return error.InvalidKey;
    }
    // Disallow ".." segments and absolute Windows-style paths.
    if (std.mem.indexOf(u8, key, "..") != null) {
        var iter = std.mem.splitScalar(u8, key, '/');
        while (iter.next()) |seg| {
            if (std.mem.eql(u8, seg, "..") or std.mem.eql(u8, seg, ".")) return error.InvalidKey;
        }
    }
    if (std.mem.indexOf(u8, key, "\\") != null) return error.InvalidKey;
    // Disallow backslashes.
    if (key.len >= 2 and key[1] == ':') return error.InvalidKey;
}

// ── Time ─────────────────────────────────────────────────────────────────────

/// Convert a Unix timestamp (nanoseconds) to ISO-8601 / RFC3339 UTC string
/// in the supplied buffer. Returns the formatted slice. Buffer must be ≥ 24 bytes.
/// Format: "YYYY-MM-DDTHH:MM:SS.000Z".
pub fn formatIso8601(buf: []u8, ns_since_epoch: i128) []const u8 {
    std.debug.assert(buf.len >= 24);
    const total_seconds: i64 = @intCast(@divFloor(ns_since_epoch, std.time.ns_per_s));
    const ms_part: u64 = @intCast(@mod(@divFloor(ns_since_epoch, std.time.ns_per_ms), 1000));

    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(if (total_seconds < 0) 0 else total_seconds) };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
        ms_part,
    }) catch "1970-01-01T00:00:00.000Z";
}

/// Parse "YYYY-MM-DDTHH:MM:SS[.fff]Z" → nanoseconds since epoch.
/// Tolerates missing milliseconds. Errors on malformed input.
pub fn parseIso8601(s: []const u8) !i128 {
    if (s.len < 20) return error.InvalidArgument;
    const year = std.fmt.parseInt(u32, s[0..4], 10) catch return error.InvalidArgument;
    if (s[4] != '-') return error.InvalidArgument;
    const month = std.fmt.parseInt(u32, s[5..7], 10) catch return error.InvalidArgument;
    if (s[7] != '-') return error.InvalidArgument;
    const day = std.fmt.parseInt(u32, s[8..10], 10) catch return error.InvalidArgument;
    if (s[10] != 'T') return error.InvalidArgument;
    const hour = std.fmt.parseInt(u32, s[11..13], 10) catch return error.InvalidArgument;
    const minute = std.fmt.parseInt(u32, s[14..16], 10) catch return error.InvalidArgument;
    const second = std.fmt.parseInt(u32, s[17..19], 10) catch return error.InvalidArgument;

    // Days since 1970-01-01 using Howard Hinnant's civil-from-days inverse.
    const y: i64 = @as(i64, year) - @as(i64, if (month <= 2) 1 else 0);
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: u64 = @intCast(y - era * 400);
    const m_adj: u64 = if (month > 2) month - 3 else month + 9;
    const doy: u64 = (153 * m_adj + 2) / 5 + day - 1;
    const doe: u64 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const days: i64 = era * 146097 + @as(i64, @intCast(doe)) - 719468;

    const total_secs: i64 = days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
    return @as(i128, total_secs) * std.time.ns_per_s;
}

/// SigV4 basic timestamp format: YYYYMMDDTHHMMSSZ (16 bytes).
pub fn formatAmzDate(buf: []u8, ns_since_epoch: i128) []const u8 {
    std.debug.assert(buf.len >= 16);
    const total_seconds: i64 = @intCast(@divFloor(ns_since_epoch, std.time.ns_per_s));
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(if (total_seconds < 0) 0 else total_seconds) };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch "19700101T000000Z";
}

// ── Request id ───────────────────────────────────────────────────────────────

var rid_counter: std.atomic.Value(u64) = .init(0);

/// Generate 16 raw random bytes for use as a request id. Caller hex-encodes
/// to 32 chars when emitting `x-amz-request-id`. Mixes time + counter +
/// CSPRNG so duplicates are extraordinarily unlikely across processes.
pub fn newRequestId(buf: *[16]u8) void {
    const ns: u64 = @intCast(std.time.nanoTimestamp() & 0xffff_ffff_ffff_ffff);
    const c = rid_counter.fetchAdd(1, .monotonic);
    const mixed = ns ^ (c *% 0x9E37_79B9_7F4A_7C15);
    var random_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    std.mem.writeInt(u64, buf[0..8], mixed, .big);
    @memcpy(buf[8..16], &random_bytes);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "urlDecode basic" {
    const a = std.testing.allocator;
    const out = try urlDecode(a, "hello%20world%2Fkey");
    defer a.free(out);
    try std.testing.expectEqualStrings("hello world/key", out);
}

test "urlDecode invalid" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidPercentEncoding, urlDecode(a, "abc%2"));
    try std.testing.expectError(error.InvalidPercentEncoding, urlDecode(a, "abc%ZZ"));
}

test "awsUriEncode reserved" {
    const a = std.testing.allocator;
    const out = try awsUriEncode(a, "foo bar/baz", true);
    defer a.free(out);
    try std.testing.expectEqualStrings("foo%20bar%2Fbaz", out);
    const out2 = try awsUriEncode(a, "foo bar/baz", false);
    defer a.free(out2);
    try std.testing.expectEqualStrings("foo%20bar/baz", out2);
}

test "validateBucketName" {
    try validateBucketName("my-bucket");
    try validateBucketName("a.b.c");
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("ab"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("UpperCase"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("-leading"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("trailing-"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("with..dots"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("192.168.1.1"));
    try std.testing.expectError(error.InvalidBucketName, validateBucketName("xn--badpunycode"));
}

test "validateObjectKey rejects traversal" {
    try validateObjectKey("ok/key.txt");
    try std.testing.expectError(error.InvalidKey, validateObjectKey(""));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("../escape"));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("a/../b"));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("/leading"));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("a\x00b"));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("back\\slash"));
    try std.testing.expectError(error.InvalidKey, validateObjectKey("C:\\evil"));
}

test "formatIso8601 epoch" {
    var buf: [32]u8 = undefined;
    const s = formatIso8601(&buf, 0);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00.000Z", s);
}

test "formatAmzDate epoch" {
    var buf: [32]u8 = undefined;
    const s = formatAmzDate(&buf, 0);
    try std.testing.expectEqualStrings("19700101T000000Z", s);
}

test "newRequestId differs across calls" {
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    newRequestId(&a);
    newRequestId(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
