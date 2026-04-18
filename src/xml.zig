//! XML response builder for S3-compatible API responses.
//! Generates well-formed XML without external dependencies.
const std = @import("std");
const Allocator = std.mem.Allocator;

const Self = @This();

buffer: std.ArrayList(u8),
allocator: Allocator,

/// S3 XML namespace.
pub const s3_ns = "http://s3.amazonaws.com/doc/2006-03-01/";

pub fn init(allocator: Allocator) Self {
    return .{ .buffer = .{}, .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    self.buffer.deinit(self.allocator);
}

pub fn toOwnedSlice(self: *Self) Allocator.Error![]u8 {
    return self.buffer.toOwnedSlice(self.allocator);
}

pub fn xmlHeader(self: *Self) Allocator.Error!void {
    try self.buffer.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
}

pub fn openTag(self: *Self, name: []const u8) Allocator.Error!void {
    try self.buffer.append(self.allocator, '<');
    try self.buffer.appendSlice(self.allocator, name);
    try self.buffer.append(self.allocator, '>');
}

pub fn openTagNs(self: *Self, name: []const u8, ns: []const u8) Allocator.Error!void {
    try self.buffer.append(self.allocator, '<');
    try self.buffer.appendSlice(self.allocator, name);
    try self.buffer.appendSlice(self.allocator, " xmlns=\"");
    try self.buffer.appendSlice(self.allocator, ns);
    try self.buffer.appendSlice(self.allocator, "\">");
}

pub fn closeTag(self: *Self, name: []const u8) Allocator.Error!void {
    try self.buffer.appendSlice(self.allocator, "</");
    try self.buffer.appendSlice(self.allocator, name);
    try self.buffer.append(self.allocator, '>');
}

pub fn textElement(self: *Self, name: []const u8, value: []const u8) Allocator.Error!void {
    try self.openTag(name);
    try self.escapeAndAppend(value);
    try self.closeTag(name);
}

pub fn intElement(self: *Self, name: []const u8, value: anytype) Allocator.Error!void {
    try self.openTag(name);
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{value}) catch "0";
    try self.buffer.appendSlice(self.allocator, s);
    try self.closeTag(name);
}

pub fn boolElement(self: *Self, name: []const u8, value: bool) Allocator.Error!void {
    try self.textElement(name, if (value) "true" else "false");
}

pub fn escapeAndAppend(self: *Self, text: []const u8) Allocator.Error!void {
    for (text) |c| {
        switch (c) {
            '<' => try self.buffer.appendSlice(self.allocator, "&lt;"),
            '>' => try self.buffer.appendSlice(self.allocator, "&gt;"),
            '&' => try self.buffer.appendSlice(self.allocator, "&amp;"),
            '"' => try self.buffer.appendSlice(self.allocator, "&quot;"),
            '\'' => try self.buffer.appendSlice(self.allocator, "&apos;"),
            else => try self.buffer.append(self.allocator, c),
        }
    }
}

// ── S3 response data structures ──────────────────────────────────────────────

pub const BucketInfo = struct {
    name: []const u8,
    creation_date: []const u8,
};

pub const ObjectInfo = struct {
    key: []const u8,
    last_modified: []const u8,
    etag: []const u8,
    size: u64,
};

pub const ListResult = struct {
    bucket: []const u8,
    prefix: []const u8,
    delimiter: []const u8,
    continuation_token: []const u8,
    next_continuation_token: []const u8,
    start_after: []const u8,
    max_keys: usize,
    is_truncated: bool,
    key_count: usize,
    objects: []const ObjectInfo,
    common_prefixes: []const []const u8,
};

pub const DeleteRequestEntry = struct {
    key: []const u8,
    version_id: []const u8 = "",
};

pub const DeleteResultEntry = struct {
    key: []const u8,
    /// If non-empty, this entry failed and the others are ignored.
    code: []const u8 = "",
    message: []const u8 = "",
};

pub const PartInfo = struct {
    part_number: u32,
    etag: []const u8,
    size: u64,
    last_modified: []const u8,
};

pub const TagPair = struct { key: []const u8, value: []const u8 };

pub const InProgressUpload = struct {
    key: []const u8,
    upload_id: []const u8,
    initiated: []const u8,
};

// ── Builders ─────────────────────────────────────────────────────────────────

pub fn buildError(
    allocator: Allocator,
    code: []const u8,
    message: []const u8,
    resource: []const u8,
    request_id: []const u8,
) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTag("Error");
    try x.textElement("Code", code);
    try x.textElement("Message", message);
    try x.textElement("Resource", resource);
    try x.textElement("RequestId", request_id);
    try x.closeTag("Error");
    return x.toOwnedSlice();
}

pub fn buildListBuckets(allocator: Allocator, buckets: []const BucketInfo) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("ListAllMyBucketsResult", s3_ns);
    try x.openTag("Owner");
    try x.textElement("ID", "simpaniz");
    try x.textElement("DisplayName", "simpaniz");
    try x.closeTag("Owner");
    try x.openTag("Buckets");
    for (buckets) |b| {
        try x.openTag("Bucket");
        try x.textElement("Name", b.name);
        try x.textElement("CreationDate", b.creation_date);
        try x.closeTag("Bucket");
    }
    try x.closeTag("Buckets");
    try x.closeTag("ListAllMyBucketsResult");
    return x.toOwnedSlice();
}

pub fn buildListObjects(allocator: Allocator, r: ListResult) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("ListBucketResult", s3_ns);
    try x.textElement("Name", r.bucket);
    try x.textElement("Prefix", r.prefix);
    if (r.delimiter.len > 0) try x.textElement("Delimiter", r.delimiter);
    try x.intElement("KeyCount", r.key_count);
    try x.intElement("MaxKeys", r.max_keys);
    try x.boolElement("IsTruncated", r.is_truncated);
    if (r.continuation_token.len > 0) try x.textElement("ContinuationToken", r.continuation_token);
    if (r.next_continuation_token.len > 0) try x.textElement("NextContinuationToken", r.next_continuation_token);
    if (r.start_after.len > 0) try x.textElement("StartAfter", r.start_after);
    for (r.objects) |obj| {
        try x.openTag("Contents");
        try x.textElement("Key", obj.key);
        try x.textElement("LastModified", obj.last_modified);
        try x.textElement("ETag", obj.etag);
        try x.intElement("Size", obj.size);
        try x.textElement("StorageClass", "STANDARD");
        try x.closeTag("Contents");
    }
    for (r.common_prefixes) |cp| {
        try x.openTag("CommonPrefixes");
        try x.textElement("Prefix", cp);
        try x.closeTag("CommonPrefixes");
    }
    try x.closeTag("ListBucketResult");
    return x.toOwnedSlice();
}

pub fn buildListObjectVersions(
    allocator: Allocator,
    bucket: []const u8,
    prefix: []const u8,
    versions: []const VersionInfo,
) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("ListVersionsResult", s3_ns);
    try x.textElement("Name", bucket);
    try x.textElement("Prefix", prefix);
    try x.textElement("KeyMarker", "");
    try x.textElement("VersionIdMarker", "");
    try x.intElement("MaxKeys", 1000);
    try x.boolElement("IsTruncated", false);
    for (versions) |v| {
        const tag: []const u8 = if (v.is_delete_marker) "DeleteMarker" else "Version";
        try x.openTag(tag);
        try x.textElement("Key", v.key);
        try x.textElement("VersionId", v.version_id);
        try x.boolElement("IsLatest", v.is_latest);
        try x.textElement("LastModified", v.last_modified);
        if (!v.is_delete_marker) {
            try x.openTag("ETag");
            try x.buffer.appendSlice(x.allocator, "&quot;");
            try x.escapeAndAppend(v.etag);
            try x.buffer.appendSlice(x.allocator, "&quot;");
            try x.closeTag("ETag");
            try x.intElement("Size", v.size);
            try x.textElement("StorageClass", "STANDARD");
        }
        try x.closeTag(tag);
    }
    try x.closeTag("ListVersionsResult");
    return x.toOwnedSlice();
}

pub const VersionInfo = struct {
    key: []const u8,
    version_id: []const u8,
    is_delete_marker: bool,
    is_latest: bool,
    last_modified: []const u8,
    etag: []const u8,
    size: u64,
};

pub fn buildCopyObjectResult(allocator: Allocator, etag_hex: []const u8, last_modified: []const u8) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("CopyObjectResult", s3_ns);
    try x.openTag("LastModified");
    try x.escapeAndAppend(last_modified);
    try x.closeTag("LastModified");
    try x.openTag("ETag");
    try x.buffer.appendSlice(x.allocator, "&quot;");
    try x.escapeAndAppend(etag_hex);
    try x.buffer.appendSlice(x.allocator, "&quot;");
    try x.closeTag("ETag");
    try x.closeTag("CopyObjectResult");
    return x.toOwnedSlice();
}

pub fn buildInitiateMultipart(allocator: Allocator, bucket: []const u8, key: []const u8, upload_id: []const u8) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("InitiateMultipartUploadResult", s3_ns);
    try x.textElement("Bucket", bucket);
    try x.textElement("Key", key);
    try x.textElement("UploadId", upload_id);
    try x.closeTag("InitiateMultipartUploadResult");
    return x.toOwnedSlice();
}

pub fn buildCompleteMultipart(allocator: Allocator, location: []const u8, bucket: []const u8, key: []const u8, etag_quoted: []const u8) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("CompleteMultipartUploadResult", s3_ns);
    try x.textElement("Location", location);
    try x.textElement("Bucket", bucket);
    try x.textElement("Key", key);
    try x.textElement("ETag", etag_quoted);
    try x.closeTag("CompleteMultipartUploadResult");
    return x.toOwnedSlice();
}

pub fn buildListParts(allocator: Allocator, bucket: []const u8, key: []const u8, upload_id: []const u8, parts: []const PartInfo) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("ListPartsResult", s3_ns);
    try x.textElement("Bucket", bucket);
    try x.textElement("Key", key);
    try x.textElement("UploadId", upload_id);
    try x.intElement("MaxParts", 10_000);
    try x.boolElement("IsTruncated", false);
    for (parts) |p| {
        try x.openTag("Part");
        try x.intElement("PartNumber", p.part_number);
        try x.textElement("LastModified", p.last_modified);
        try x.textElement("ETag", p.etag);
        try x.intElement("Size", p.size);
        try x.closeTag("Part");
    }
    try x.closeTag("ListPartsResult");
    return x.toOwnedSlice();
}

pub fn buildDeleteResult(allocator: Allocator, deleted: []const DeleteResultEntry, errors: []const DeleteResultEntry, quiet: bool) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("DeleteResult", s3_ns);
    if (!quiet) {
        for (deleted) |d| {
            try x.openTag("Deleted");
            try x.textElement("Key", d.key);
            try x.closeTag("Deleted");
        }
    }
    for (errors) |e| {
        try x.openTag("Error");
        try x.textElement("Key", e.key);
        try x.textElement("Code", e.code);
        try x.textElement("Message", e.message);
        try x.closeTag("Error");
    }
    try x.closeTag("DeleteResult");
    return x.toOwnedSlice();
}

pub fn buildTagging(allocator: Allocator, tags: []const TagPair) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("Tagging", s3_ns);
    try x.openTag("TagSet");
    for (tags) |t| {
        try x.openTag("Tag");
        try x.textElement("Key", t.key);
        try x.textElement("Value", t.value);
        try x.closeTag("Tag");
    }
    try x.closeTag("TagSet");
    try x.closeTag("Tagging");
    return x.toOwnedSlice();
}

pub fn buildListMultipartUploads(
    allocator: Allocator,
    bucket: []const u8,
    uploads: []const InProgressUpload,
) Allocator.Error![]u8 {
    var x = init(allocator);
    defer x.deinit();
    try x.xmlHeader();
    try x.openTagNs("ListMultipartUploadsResult", s3_ns);
    try x.textElement("Bucket", bucket);
    try x.textElement("KeyMarker", "");
    try x.textElement("UploadIdMarker", "");
    try x.intElement("MaxUploads", 1000);
    try x.boolElement("IsTruncated", false);
    for (uploads) |u| {
        try x.openTag("Upload");
        try x.textElement("Key", u.key);
        try x.textElement("UploadId", u.upload_id);
        try x.openTag("Initiator");
        try x.textElement("ID", "simpaniz");
        try x.textElement("DisplayName", "simpaniz");
        try x.closeTag("Initiator");
        try x.openTag("Owner");
        try x.textElement("ID", "simpaniz");
        try x.textElement("DisplayName", "simpaniz");
        try x.closeTag("Owner");
        try x.textElement("StorageClass", "STANDARD");
        try x.textElement("Initiated", u.initiated);
        try x.closeTag("Upload");
    }
    try x.closeTag("ListMultipartUploadsResult");
    return x.toOwnedSlice();
}

/// Parse a `<Tagging><TagSet><Tag><Key>..</Key><Value>..</Value></Tag>..`
/// document into a list of `(key, value)` pairs (subslices of `body`).
/// Caller frees the slice.
pub fn parseTagging(allocator: Allocator, body: []const u8) Allocator.Error![]TagPair {
    var out = std.ArrayList(TagPair){};
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, body, i, "<Tag>")) |tag_open| {
        const tag_close = std.mem.indexOfPos(u8, body, tag_open, "</Tag>") orelse break;
        const inner = body[tag_open + "<Tag>".len .. tag_close];
        const k = sliceBetween(inner, "<Key>", "</Key>") orelse "";
        const v = sliceBetween(inner, "<Value>", "</Value>") orelse "";
        try out.append(allocator, .{ .key = k, .value = v });
        i = tag_close + "</Tag>".len;
    }
    return out.toOwnedSlice(allocator);
}

fn sliceBetween(haystack: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    const a = std.mem.indexOf(u8, haystack, open) orelse return null;
    const b = std.mem.indexOfPos(u8, haystack, a + open.len, close) orelse return null;
    return haystack[a + open.len .. b];
}

// ── Tiny XML parser for Delete and CompleteMultipart bodies ──────────────────

/// Extract all values of `<tag>VALUE</tag>` (returns subslices of `body`).
pub fn collectTagValues(allocator: Allocator, body: []const u8, tag: []const u8) Allocator.Error![][]const u8 {
    var out = std.ArrayList([]const u8){};
    errdefer out.deinit(allocator);

    const open = try std.fmt.allocPrint(allocator, "<{s}>", .{tag});
    defer allocator.free(open);
    const close = try std.fmt.allocPrint(allocator, "</{s}>", .{tag});
    defer allocator.free(close);

    var i: usize = 0;
    while (std.mem.indexOfPos(u8, body, i, open)) |p| {
        const start = p + open.len;
        const end_off = std.mem.indexOfPos(u8, body, start, close) orelse break;
        try out.append(allocator, body[start..end_off]);
        i = end_off + close.len;
    }
    return out.toOwnedSlice(allocator);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "buildError contains code" {
    const a = std.testing.allocator;
    const out = try buildError(a, "NoSuchBucket", "missing", "/foo", "rid-1");
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Code>NoSuchBucket</Code>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<RequestId>rid-1</RequestId>") != null);
}

test "escape special characters" {
    const a = std.testing.allocator;
    var x = init(a);
    defer x.deinit();
    try x.escapeAndAppend("<a&b>\"'");
    const out = try x.toOwnedSlice();
    defer a.free(out);
    try std.testing.expectEqualStrings("&lt;a&amp;b&gt;&quot;&apos;", out);
}

test "collectTagValues" {
    const a = std.testing.allocator;
    const body = "<Delete><Object><Key>a</Key></Object><Object><Key>b/c</Key></Object></Delete>";
    const keys = try collectTagValues(a, body, "Key");
    defer a.free(keys);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualStrings("a", keys[0]);
    try std.testing.expectEqualStrings("b/c", keys[1]);
}

test "buildListObjects pagination fields" {
    const a = std.testing.allocator;
    const objs = [_]ObjectInfo{.{ .key = "k", .last_modified = "t", .etag = "\"e\"", .size = 1 }};
    const cps = [_][]const u8{"prefix/"};
    const out = try buildListObjects(a, .{
        .bucket = "b",
        .prefix = "p",
        .delimiter = "/",
        .continuation_token = "",
        .next_continuation_token = "next",
        .start_after = "",
        .max_keys = 10,
        .is_truncated = true,
        .key_count = 1,
        .objects = &objs,
        .common_prefixes = &cps,
    });
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Delimiter>/</Delimiter>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<NextContinuationToken>next</NextContinuationToken>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<CommonPrefixes><Prefix>prefix/</Prefix></CommonPrefixes>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<IsTruncated>true</IsTruncated>") != null);
}

test "parseTagging extracts pairs" {
    const a = std.testing.allocator;
    const body = "<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>core</Value></Tag></TagSet></Tagging>";
    const pairs = try parseTagging(a, body);
    defer a.free(pairs);
    try std.testing.expectEqual(@as(usize, 2), pairs.len);
    try std.testing.expectEqualStrings("env", pairs[0].key);
    try std.testing.expectEqualStrings("prod", pairs[0].value);
    try std.testing.expectEqualStrings("team", pairs[1].key);
    try std.testing.expectEqualStrings("core", pairs[1].value);
}

test "buildTagging round-trips" {
    const a = std.testing.allocator;
    const tags = [_]TagPair{ .{ .key = "k", .value = "v" } };
    const out = try buildTagging(a, &tags);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Key>k</Key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Value>v</Value>") != null);
}

test "buildListMultipartUploads emits Upload entries" {
    const a = std.testing.allocator;
    const ups = [_]InProgressUpload{
        .{ .key = "k1", .upload_id = "u1", .initiated = "2024-01-01T00:00:00.000Z" },
    };
    const out = try buildListMultipartUploads(a, "b", &ups);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Bucket>b</Bucket>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<UploadId>u1</UploadId>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<Key>k1</Key>") != null);
}
