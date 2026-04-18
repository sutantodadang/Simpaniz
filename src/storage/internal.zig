//! Helpers shared across the storage submodules: metadata sidecars,
//! tiny JSON extractor, digest streaming, base64, dir pruning.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const Io = std.Io;
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;

const paths = @import("paths.zig");
const types = @import("types.zig");
const Error = types.Error;
const ObjectMeta = types.ObjectMeta;
const EncryptionInfo = types.EncryptionInfo;

pub fn writeMetadata(bd: Dir, allocator: Allocator, key: []const u8, meta: ObjectMeta) Error!void {
    const meta_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, key }) catch return error.OutOfMemory;
    defer allocator.free(meta_path);
    if (std.fs.path.dirname(meta_path)) |parent| bd.makePath(parent) catch {};
    const json = if (meta.encryption) |enc|
        std.fmt.allocPrint(
            allocator,
            "{{\"content_type\":\"{s}\",\"etag\":\"{s}\",\"size\":{d},\"mtime_ns\":{d}," ++
                "\"enc_alg\":\"{s}\",\"enc_chunk_size\":{d},\"enc_plaintext_size\":{d}," ++
                "\"enc_wrapped_dek\":\"{s}\",\"enc_wrap_nonce\":\"{s}\"}}",
            .{ meta.content_type, meta.etag, meta.size, meta.mtime_ns, enc.alg, enc.chunk_size, enc.plaintext_size, enc.wrapped_dek_b64, enc.wrap_nonce_b64 },
        ) catch return error.OutOfMemory
    else
        std.fmt.allocPrint(
            allocator,
            "{{\"content_type\":\"{s}\",\"etag\":\"{s}\",\"size\":{d},\"mtime_ns\":{d}}}",
            .{ meta.content_type, meta.etag, meta.size, meta.mtime_ns },
        ) catch return error.OutOfMemory;
    defer allocator.free(json);
    bd.writeFile(.{ .sub_path = meta_path, .data = json }) catch return error.Internal;
}

pub fn readMetadata(bd: Dir, allocator: Allocator, key: []const u8) !ObjectMeta {
    const meta_path = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, key });
    defer allocator.free(meta_path);
    var buf: [4096]u8 = undefined;
    const json = bd.readFile(meta_path, &buf) catch {
        const stat = try bd.statFile(key);
        return .{
            .content_type = try allocator.dupe(u8, "application/octet-stream"),
            .etag = try allocator.dupe(u8, "unknown"),
            .size = stat.size,
            .mtime_ns = stat.mtime,
        };
    };
    const stat = try bd.statFile(key);

    // Encryption sidecar fields (optional).
    var encryption: ?EncryptionInfo = null;
    if (extractJson(json, "enc_alg")) |alg| {
        const chunk_s = extractJson(json, "enc_chunk_size") orelse "0";
        const pt_s = extractJson(json, "enc_plaintext_size") orelse "0";
        const wrapped = extractJson(json, "enc_wrapped_dek") orelse "";
        const nonce = extractJson(json, "enc_wrap_nonce") orelse "";
        encryption = .{
            .alg = try allocator.dupe(u8, alg),
            .chunk_size = std.fmt.parseInt(u32, chunk_s, 10) catch 0,
            .plaintext_size = std.fmt.parseInt(u64, pt_s, 10) catch 0,
            .wrapped_dek_b64 = try allocator.dupe(u8, wrapped),
            .wrap_nonce_b64 = try allocator.dupe(u8, nonce),
        };
    }

    const reported_size: u64 = if (encryption) |e| e.plaintext_size else stat.size;
    return .{
        .content_type = try allocator.dupe(u8, extractJson(json, "content_type") orelse "application/octet-stream"),
        .etag = try allocator.dupe(u8, extractJson(json, "etag") orelse "unknown"),
        .size = reported_size,
        .mtime_ns = stat.mtime,
        .encryption = encryption,
    };
}

pub fn extractJson(json: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < json.len) : (i += 1) {
        if (json[i] != '"') continue;
        const ks = i + 1;
        const ke = ks + key.len;
        if (ke >= json.len) return null;
        if (!std.mem.eql(u8, json[ks..ke], key) or json[ke] != '"') continue;
        var j = ke + 1;
        while (j < json.len and json[j] != ':') : (j += 1) {}
        if (j >= json.len) return null;
        j += 1;
        while (j < json.len and (json[j] == ' ' or json[j] == '\t')) : (j += 1) {}
        if (j >= json.len) return null;
        if (json[j] == '"') {
            const vs = j + 1;
            var ve = vs;
            while (ve < json.len and json[ve] != '"') : (ve += 1) {}
            return json[vs..ve];
        }
        const vs = j;
        var ve = j;
        while (ve < json.len and json[ve] != ',' and json[ve] != '}') : (ve += 1) {}
        return json[vs..ve];
    }
    return null;
}

pub fn streamWithDigest(reader: *Io.Reader, writer: *Io.Writer, n: u64, md5: *Md5, sha: *Sha256) !u64 {
    var remaining = n;
    var buf: [64 * 1024]u8 = undefined;
    while (remaining > 0) {
        const want = @min(remaining, buf.len);
        const got = try reader.readSliceShort(buf[0..want]);
        if (got == 0) break;
        md5.update(buf[0..got]);
        sha.update(buf[0..got]);
        try writer.writeAll(buf[0..got]);
        remaining -= got;
    }
    return n - remaining;
}

pub fn syncDir(d: Dir) !void {
    // best-effort fsync; not all platforms allow fsync on a directory handle.
    _ = d;
}

pub fn decodeBase64(allocator: Allocator, input: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(input) catch return error.BadDigest;
    const out = try allocator.alloc(u8, len);
    decoder.decode(out, input) catch {
        allocator.free(out);
        return error.BadDigest;
    };
    return out;
}

pub fn pruneEmptyParents(bd: Dir, child_path: []const u8) void {
    var path = child_path;
    while (std.fs.path.dirname(path)) |parent| {
        if (parent.len == 0) return;
        if (std.mem.eql(u8, parent, paths.meta_dir) or
            std.mem.eql(u8, parent, paths.mp_dir) or
            std.mem.eql(u8, parent, paths.tmp_dir) or
            std.mem.eql(u8, parent, paths.tags_dir)) return;
        bd.deleteDir(parent) catch return;
        path = parent;
    }
}

pub fn ensureUploadExists(bd: Dir, allocator: Allocator, upload_id: []const u8) Error!void {
    const upload_root = std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(upload_root);
    bd.access(upload_root, .{}) catch return error.UploadNotFound;
}

test "extractJson parses string and number" {
    const j = "{\"a\":\"hello\",\"b\":42}";
    try std.testing.expectEqualStrings("hello", extractJson(j, "a").?);
    try std.testing.expectEqualStrings("42", extractJson(j, "b").?);
    try std.testing.expect(extractJson(j, "missing") == null);
}

test "decodeBase64" {
    const a = std.testing.allocator;
    const out = try decodeBase64(a, "aGVsbG8=");
    defer a.free(out);
    try std.testing.expectEqualStrings("hello", out);
}
