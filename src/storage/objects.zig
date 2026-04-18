const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const File = std.fs.File;
const Io = std.Io;
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../util.zig");
const xml = @import("../xml.zig");
const paths = @import("paths.zig");
const types = @import("types.zig");
const internal = @import("internal.zig");
const sse = @import("sse.zig");

const Error = types.Error;
const ObjectMeta = types.ObjectMeta;
const PutInput = types.PutInput;
const ListOpts = types.ListOpts;
const ListPage = types.ListPage;
const EncryptionInfo = types.EncryptionInfo;

/// Stream a body of `content_length` bytes from `body_reader` into a temp file,
/// compute MD5+SHA256, optionally verify against caller hashes, fsync, and
/// atomically rename into place. Writes a sidecar metadata JSON.
pub fn putObjectStreaming(
    data_dir: Dir,
    allocator: Allocator,
    input: PutInput,
    body_reader: *Io.Reader,
) Error!ObjectMeta {
    util.validateObjectKey(input.key) catch return error.InvalidKey;

    var bd = data_dir.openDir(input.bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();

    if (std.fs.path.dirname(input.key)) |parent| {
        bd.makePath(parent) catch return error.Internal;
        const meta_parent = std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.meta_dir, parent }) catch return error.OutOfMemory;
        defer allocator.free(meta_parent);
        bd.makePath(meta_parent) catch return error.Internal;
    }

    var rand_bytes: [12]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var tmp_name_buf: [80]u8 = undefined;
    var hex_buf: [24]u8 = undefined;
    util.hexEncodeBuf(&rand_bytes, &hex_buf);
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}/upload-{s}", .{ paths.tmp_dir, hex_buf[0 .. rand_bytes.len * 2] }) catch return error.Internal;

    var tmp_file = bd.createFile(tmp_name, .{ .read = false, .truncate = true, .exclusive = true }) catch return error.Internal;
    var write_buf: [64 * 1024]u8 = undefined;
    var fw = tmp_file.writer(&write_buf);
    var md5 = Md5.init(.{});
    var sha = Sha256.init(.{});

    // SSE: capture wrapping params if encryption requested. Plaintext digests
    // are computed via a tee-style pre-encryption read.
    var dek: [sse.dek_size]u8 = undefined;
    var wrap_info: ?struct { wrapped: [sse.wrapped_dek_len]u8, nonce: [sse.nonce_size]u8 } = null;
    if (input.master_key) |mk| {
        dek = sse.generateDek();
        const w = sse.wrapDek(mk, &dek);
        wrap_info = .{ .wrapped = w.wrapped, .nonce = w.nonce };
    }

    const written: u64 = if (input.master_key != null) blk: {
        // Chunked SSE: write header, then per-chunk read → digest → encrypt.
        sse.writeHeaderTo(&fw.interface, sse.default_chunk_size) catch {
            tmp_file.close();
            bd.deleteFile(tmp_name) catch {};
            return error.Internal;
        };
        const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
        var ct_buf: [sse.default_chunk_size]u8 = undefined;
        var pt_buf: [sse.default_chunk_size]u8 = undefined;
        var remaining = input.content_length;
        var index: u64 = 0;
        while (remaining > 0) {
            const want: usize = @intCast(@min(remaining, @as(u64, sse.default_chunk_size)));
            body_reader.readSliceAll(pt_buf[0..want]) catch {
                tmp_file.close();
                bd.deleteFile(tmp_name) catch {};
                return error.BadDigest;
            };
            md5.update(pt_buf[0..want]);
            sha.update(pt_buf[0..want]);
            var nonce: [sse.nonce_size]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            var tag: [sse.tag_size]u8 = undefined;
            const aad = sse.aadForChunk(index);
            Aes256Gcm.encrypt(ct_buf[0..want], &tag, pt_buf[0..want], &aad, nonce, dek);
            fw.interface.writeAll(&nonce) catch {
                tmp_file.close();
                bd.deleteFile(tmp_name) catch {};
                return error.Internal;
            };
            fw.interface.writeAll(ct_buf[0..want]) catch {
                tmp_file.close();
                bd.deleteFile(tmp_name) catch {};
                return error.Internal;
            };
            fw.interface.writeAll(&tag) catch {
                tmp_file.close();
                bd.deleteFile(tmp_name) catch {};
                return error.Internal;
            };
            remaining -= want;
            index += 1;
        }
        break :blk input.content_length;
    } else internal.streamWithDigest(body_reader, &fw.interface, input.content_length, &md5, &sha) catch {
        tmp_file.close();
        bd.deleteFile(tmp_name) catch {};
        return error.Internal;
    };
    fw.interface.flush() catch {
        tmp_file.close();
        bd.deleteFile(tmp_name) catch {};
        return error.Internal;
    };
    tmp_file.sync() catch {};
    tmp_file.close();

    if (written != input.content_length) {
        bd.deleteFile(tmp_name) catch {};
        return error.BadDigest;
    }

    var md5_digest: [16]u8 = undefined;
    md5.final(&md5_digest);
    const md5_hex = util.hexEncodeMd5(md5_digest);

    if (input.expected_md5_b64.len > 0) {
        const expected = internal.decodeBase64(allocator, input.expected_md5_b64) catch {
            bd.deleteFile(tmp_name) catch {};
            return error.BadDigest;
        };
        defer allocator.free(expected);
        if (expected.len != 16 or !std.mem.eql(u8, expected, &md5_digest)) {
            bd.deleteFile(tmp_name) catch {};
            return error.BadDigest;
        }
    }
    if (input.expected_sha256_hex.len > 0 and !std.mem.eql(u8, input.expected_sha256_hex, "UNSIGNED-PAYLOAD") and !std.mem.eql(u8, input.expected_sha256_hex, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")) {
        var sha_digest: [32]u8 = undefined;
        sha.final(&sha_digest);
        const sha_hex = util.hexEncodeSha256(sha_digest);
        if (!std.mem.eql(u8, &sha_hex, input.expected_sha256_hex)) {
            bd.deleteFile(tmp_name) catch {};
            return error.BadDigest;
        }
    }

    bd.rename(tmp_name, input.key) catch {
        bd.deleteFile(tmp_name) catch {};
        return error.Internal;
    };

    internal.syncDir(bd) catch {};

    // Build encryption sidecar for metadata if encrypted.
    var enc_info: ?EncryptionInfo = null;
    if (wrap_info) |w| {
        const enc_b64 = std.base64.standard.Encoder;
        const wrapped_b64 = allocator.alloc(u8, enc_b64.calcSize(w.wrapped.len)) catch return error.OutOfMemory;
        _ = enc_b64.encode(wrapped_b64, &w.wrapped);
        const nonce_b64 = allocator.alloc(u8, enc_b64.calcSize(w.nonce.len)) catch return error.OutOfMemory;
        _ = enc_b64.encode(nonce_b64, &w.nonce);
        enc_info = .{
            .alg = "AES256",
            .chunk_size = sse.default_chunk_size,
            .plaintext_size = written,
            .wrapped_dek_b64 = wrapped_b64,
            .wrap_nonce_b64 = nonce_b64,
        };
    }

    try internal.writeMetadata(bd, allocator, input.key, .{
        .content_type = input.content_type,
        .etag = &md5_hex,
        .size = written,
        .mtime_ns = std.time.nanoTimestamp(),
        .encryption = enc_info,
    });

    const stat = bd.statFile(input.key) catch return error.Internal;

    return .{
        .content_type = allocator.dupe(u8, input.content_type) catch return error.OutOfMemory,
        .etag = allocator.dupe(u8, &md5_hex) catch return error.OutOfMemory,
        .size = if (enc_info != null) written else stat.size,
        .mtime_ns = stat.mtime,
        .encryption = enc_info,
    };
}

/// Reader adapter that updates MD5/SHA-256 of every byte that passes through.
/// Reserved for future use (pre-encryption digest of streamed bodies).
const DigestingReader = void;

/// Open an object for reading; returns the file handle and metadata.
/// Caller must close the file.
pub fn openObject(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8) Error!struct { file: File, meta: ObjectMeta } {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    const file = bd.openFile(key, .{}) catch return error.ObjectNotFound;
    const meta = internal.readMetadata(bd, allocator, key) catch return error.Internal;
    return .{ .file = file, .meta = meta };
}

pub fn headObject(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8) Error!ObjectMeta {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.access(key, .{}) catch return error.ObjectNotFound;
    return internal.readMetadata(bd, allocator, key) catch error.Internal;
}

pub fn deleteObject(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8) Error!void {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.deleteFile(key) catch |e| switch (e) {
        error.FileNotFound => return error.ObjectNotFound,
        else => return error.Internal,
    };
    const meta_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ paths.meta_dir, key }) catch return;
    defer allocator.free(meta_path);
    bd.deleteFile(meta_path) catch {};
    const tags_path = std.fmt.allocPrint(allocator, "{s}/{s}.xml", .{ paths.tags_dir, key }) catch return;
    defer allocator.free(tags_path);
    bd.deleteFile(tags_path) catch {};
    internal.pruneEmptyParents(bd, key);
    internal.pruneEmptyParents(bd, meta_path);
    internal.pruneEmptyParents(bd, tags_path);
}

/// Copy `src` to `dst`, possibly replacing metadata. Source and destination
/// can share a bucket. Computes a fresh ETag from the destination contents.
pub fn copyObject(
    data_dir: Dir,
    allocator: Allocator,
    src_bucket: []const u8,
    src_key: []const u8,
    dst_bucket: []const u8,
    dst_key: []const u8,
    new_content_type: ?[]const u8,
) Error!ObjectMeta {
    util.validateObjectKey(src_key) catch return error.InvalidKey;
    util.validateObjectKey(dst_key) catch return error.InvalidKey;

    var src_bd = data_dir.openDir(src_bucket, .{}) catch return error.BucketNotFound;
    defer src_bd.close();
    var src_file = src_bd.openFile(src_key, .{}) catch return error.ObjectNotFound;
    defer src_file.close();
    const src_stat = src_file.stat() catch return error.Internal;

    const src_meta = internal.readMetadata(src_bd, allocator, src_key) catch return error.Internal;
    defer {
        allocator.free(src_meta.content_type);
        allocator.free(src_meta.etag);
        if (src_meta.encryption) |e| {
            allocator.free(e.alg);
            allocator.free(e.wrapped_dek_b64);
            allocator.free(e.wrap_nonce_b64);
        }
    }
    // Copying SSE-encrypted source is not supported in this cut (would require
    // decrypting on read and re-encrypting on write; currently we'd copy the
    // ciphertext as plaintext, corrupting the destination).
    if (src_meta.encryption != null) return error.Internal;
    const ct = if (new_content_type) |c| c else src_meta.content_type;

    var read_buf: [64 * 1024]u8 = undefined;
    var fr = src_file.reader(&read_buf);

    return putObjectStreaming(data_dir, allocator, .{
        .bucket = dst_bucket,
        .key = dst_key,
        .content_type = ct,
        .content_length = src_stat.size,
    }, &fr.interface);
}

/// List objects with optional prefix, delimiter (always "/" or empty), continuation, start-after, max-keys.
/// Caller owns returned slices.
pub fn listObjects(data_dir: Dir, allocator: Allocator, bucket: []const u8, opts: ListOpts) Error!ListPage {
    util.validateBucketName(bucket) catch return error.InvalidKey;

    var bd = data_dir.openDir(bucket, .{ .iterate = true }) catch return error.BucketNotFound;
    defer bd.close();

    var all = std.ArrayList([]u8){};
    defer {
        for (all.items) |k| allocator.free(k);
        all.deinit(allocator);
    }

    var walker = bd.walk(allocator) catch return error.OutOfMemory;
    defer walker.deinit();
    while (walker.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.path, paths.reserved_prefix)) continue;
        const normalized = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
        for (normalized) |*c| if (c.* == '\\') {
            c.* = '/';
        };
        if (opts.prefix.len > 0 and !std.mem.startsWith(u8, normalized, opts.prefix)) {
            allocator.free(normalized);
            continue;
        }
        all.append(allocator, normalized) catch return error.OutOfMemory;
    }

    std.mem.sort([]u8, all.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    const start_marker: []const u8 = if (opts.continuation_token.len > 0)
        opts.continuation_token
    else if (opts.start_after.len > 0)
        opts.start_after
    else
        "";

    var objects = std.ArrayList(xml.ObjectInfo){};
    var prefixes_set = std.StringArrayHashMap(void).init(allocator);
    defer prefixes_set.deinit();
    errdefer {
        for (objects.items) |o| {
            allocator.free(o.key);
            allocator.free(o.last_modified);
            allocator.free(o.etag);
        }
        objects.deinit(allocator);
    }

    const max = if (opts.max_keys == 0 or opts.max_keys > 1000) 1000 else opts.max_keys;
    var emitted: usize = 0;
    var truncated = false;
    var next_token: []const u8 = "";

    for (all.items) |key| {
        if (start_marker.len > 0 and !std.mem.lessThan(u8, start_marker, key)) continue;

        if (opts.delimiter.len == 1 and opts.delimiter[0] == '/') {
            const suffix_start = opts.prefix.len;
            if (std.mem.indexOfScalarPos(u8, key, suffix_start, '/')) |slash| {
                const cp = key[0 .. slash + 1];
                if (!prefixes_set.contains(cp)) {
                    if (emitted >= max) {
                        truncated = true;
                        next_token = allocator.dupe(u8, key) catch return error.OutOfMemory;
                        break;
                    }
                    const cp_owned = allocator.dupe(u8, cp) catch return error.OutOfMemory;
                    prefixes_set.put(cp_owned, {}) catch return error.OutOfMemory;
                    emitted += 1;
                }
                continue;
            }
        }

        if (emitted >= max) {
            truncated = true;
            next_token = allocator.dupe(u8, key) catch return error.OutOfMemory;
            break;
        }

        const meta = internal.readMetadata(bd, allocator, key) catch ObjectMeta{
            .content_type = allocator.dupe(u8, "application/octet-stream") catch return error.OutOfMemory,
            .etag = allocator.dupe(u8, "unknown") catch return error.OutOfMemory,
            .size = 0,
            .mtime_ns = 0,
        };
        allocator.free(meta.content_type);
        const stat = bd.statFile(key) catch continue;
        var lm_buf: [32]u8 = undefined;
        const lm = util.formatIso8601(&lm_buf, stat.mtime);
        const lm_owned = allocator.dupe(u8, lm) catch return error.OutOfMemory;
        const etag_quoted = std.fmt.allocPrint(allocator, "\"{s}\"", .{meta.etag}) catch return error.OutOfMemory;
        allocator.free(meta.etag);
        const key_owned = allocator.dupe(u8, key) catch return error.OutOfMemory;
        objects.append(allocator, .{
            .key = key_owned,
            .last_modified = lm_owned,
            .etag = etag_quoted,
            .size = stat.size,
        }) catch return error.OutOfMemory;
        emitted += 1;
    }

    const cps = prefixes_set.keys();
    const cps_owned = allocator.alloc([]const u8, cps.len) catch return error.OutOfMemory;
    for (cps, 0..) |k, i| cps_owned[i] = k;

    return .{
        .objects = objects.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .common_prefixes = cps_owned,
        .is_truncated = truncated,
        .next_continuation_token = next_token,
    };
}
