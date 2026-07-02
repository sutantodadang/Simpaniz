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
const buckets = @import("buckets.zig");

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
            .alg = input.sse_alg,
            .chunk_size = sse.default_chunk_size,
            .plaintext_size = written,
            .wrapped_dek_b64 = wrapped_b64,
            .wrap_nonce_b64 = nonce_b64,
            .sse_c_key_md5 = input.sse_c_key_md5,
            .kms_key_id = input.kms_key_id,
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

/// Options controlling server-side encryption across a copy. `src_unwrap_key`
/// is the master key, needed only when the source is SSE-S3/SSE-KMS
/// encrypted (SSE-C sources are not supported by this cut). `dst_wrap_key`
/// requests encryption of the destination (master key for AES256/aws:kms,
/// or a customer key for SSE-C); null leaves the destination plaintext.
pub const CopyOpts = struct {
    src_unwrap_key: ?*const [32]u8 = null,
    dst_wrap_key: ?*const [32]u8 = null,
    dst_sse_alg: []const u8 = "AES256",
    dst_sse_c_key_md5: []const u8 = "",
    dst_kms_key_id: []const u8 = "",
};

/// Copy `src` to `dst`, possibly replacing metadata. Source and destination
/// can share a bucket. Computes a fresh ETag from the destination contents.
/// Handles SSE transparently: an encrypted source is decrypted on read, and
/// the destination is (re-)encrypted per `opts`.
pub fn copyObject(
    data_dir: Dir,
    allocator: Allocator,
    src_bucket: []const u8,
    src_key: []const u8,
    dst_bucket: []const u8,
    dst_key: []const u8,
    new_content_type: ?[]const u8,
    opts: CopyOpts,
) Error!ObjectMeta {
    util.validateObjectKey(src_key) catch return error.InvalidKey;
    util.validateObjectKey(dst_key) catch return error.InvalidKey;

    var src_bd = data_dir.openDir(src_bucket, .{}) catch return error.BucketNotFound;
    defer src_bd.close();
    var src_file = src_bd.openFile(src_key, .{}) catch return error.ObjectNotFound;
    defer src_file.close();

    const src_meta = internal.readMetadata(src_bd, allocator, src_key) catch return error.Internal;
    defer {
        allocator.free(src_meta.content_type);
        allocator.free(src_meta.etag);
        allocator.free(src_meta.storage_class);
        if (src_meta.encryption) |e| {
            allocator.free(e.alg);
            allocator.free(e.wrapped_dek_b64);
            allocator.free(e.wrap_nonce_b64);
            allocator.free(e.sse_c_key_md5);
            allocator.free(e.kms_key_id);
        }
    }
    const ct = if (new_content_type) |c| c else src_meta.content_type;
    // `src_meta.size` is already the plaintext size for both encrypted and
    // plain objects (see internal.readMetadata).
    const plaintext_len = src_meta.size;

    var read_buf: [64 * 1024]u8 = undefined;

    if (src_meta.encryption) |enc| {
        if (std.mem.eql(u8, enc.alg, "SSE-C")) return error.Internal; // needs customer key, not plumbed through copy
        const mk = opts.src_unwrap_key orelse return error.Internal;
        const wrapped_raw = internal.decodeBase64(allocator, enc.wrapped_dek_b64) catch return error.Internal;
        defer allocator.free(wrapped_raw);
        const nonce_raw = internal.decodeBase64(allocator, enc.wrap_nonce_b64) catch return error.Internal;
        defer allocator.free(nonce_raw);
        if (wrapped_raw.len != sse.wrapped_dek_len or nonce_raw.len != sse.nonce_size) return error.Internal;
        const dek = sse.unwrapDek(mk, wrapped_raw[0..sse.wrapped_dek_len], nonce_raw[0..sse.nonce_size]) catch return error.Internal;

        // Decrypt the whole object into memory, then feed it as a plain
        // reader into putObjectStreaming (which re-encrypts if requested).
        var src_read_buf: [64 * 1024]u8 = undefined;
        var src_fr = src_file.reader(&src_read_buf);
        var plain_writer = std.Io.Writer.Allocating.init(allocator);
        defer plain_writer.deinit();
        sse.decryptStream(&src_fr.interface, &plain_writer.writer, plaintext_len, &dek) catch return error.Internal;
        var fixed_reader = std.Io.Reader.fixed(plain_writer.written());

        return putObjectStreaming(data_dir, allocator, .{
            .bucket = dst_bucket,
            .key = dst_key,
            .content_type = ct,
            .content_length = plaintext_len,
            .master_key = opts.dst_wrap_key,
            .sse_alg = opts.dst_sse_alg,
            .sse_c_key_md5 = opts.dst_sse_c_key_md5,
            .kms_key_id = opts.dst_kms_key_id,
        }, &fixed_reader);
    }

    var fr = src_file.reader(&read_buf);
    return putObjectStreaming(data_dir, allocator, .{
        .bucket = dst_bucket,
        .key = dst_key,
        .content_type = ct,
        .content_length = plaintext_len,
        .master_key = opts.dst_wrap_key,
        .sse_alg = opts.dst_sse_alg,
        .sse_c_key_md5 = opts.dst_sse_c_key_md5,
        .kms_key_id = opts.dst_kms_key_id,
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
        // Resume semantics: `continuation_token` is INCLUSIVE (it is the
        // first key that was NOT emitted on the previous page, so it must be
        // emitted now — a strict-greater filter here silently dropped one
        // key per truncated page). `start_after` stays EXCLUSIVE per S3.
        if (opts.continuation_token.len > 0) {
            if (std.mem.lessThan(u8, key, opts.continuation_token)) continue; // resume AT token
        } else if (opts.start_after.len > 0) {
            if (!std.mem.lessThan(u8, opts.start_after, key)) continue; // strictly after
        }

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

// ── Tests ────────────────────────────────────────────────────────────────────

/// Frees a fresh ObjectMeta returned directly by putObjectStreaming/copyObject
/// (its `.alg`/`.sse_c_key_md5`/`.kms_key_id` are borrowed/literal, not
/// allocator-owned — only the base64 wrap fields are).
fn freeMeta(a: Allocator, meta: ObjectMeta) void {
    a.free(meta.content_type);
    a.free(meta.etag);
    if (meta.encryption) |e| {
        a.free(e.wrapped_dek_b64);
        a.free(e.wrap_nonce_b64);
    }
}

/// Frees an ObjectMeta obtained via internal.readMetadata (openObject/
/// headObject), where every encryption sub-field is allocator-duped.
fn freeReadMeta(a: Allocator, meta: ObjectMeta) void {
    a.free(meta.content_type);
    a.free(meta.etag);
    a.free(meta.storage_class);
    if (meta.encryption) |e| {
        a.free(e.alg);
        a.free(e.wrapped_dek_b64);
        a.free(e.wrap_nonce_b64);
        a.free(e.sse_c_key_md5);
        a.free(e.kms_key_id);
    }
}

test "copyObject encrypted source to plaintext destination" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try buckets.createBucket(tmp.dir, "buk");

    var master: [32]u8 = undefined;
    std.crypto.random.bytes(&master);

    const plaintext = "the quick brown fox jumps over the lazy dog" ** 50;
    var pr = Io.Reader.fixed(plaintext);
    const put_meta = try putObjectStreaming(tmp.dir, a, .{
        .bucket = "buk",
        .key = "src-enc",
        .content_length = plaintext.len,
        .master_key = &master,
    }, &pr);
    defer freeMeta(a, put_meta);

    const copy_meta = try copyObject(tmp.dir, a, "buk", "src-enc", "buk", "dst-plain", null, .{
        .src_unwrap_key = &master,
    });
    defer freeMeta(a, copy_meta);

    try std.testing.expect(copy_meta.encryption == null);

    var bd = try tmp.dir.openDir("buk", .{});
    defer bd.close();
    const got = try bd.readFileAlloc(a, "dst-plain", 1024 * 1024);
    defer a.free(got);
    try std.testing.expectEqualStrings(plaintext, got);
}

test "copyObject plaintext source to encrypted destination" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try buckets.createBucket(tmp.dir, "buk");

    var master: [32]u8 = undefined;
    std.crypto.random.bytes(&master);

    const plaintext = "another round of copy testing, now going the other way." ** 30;
    var pr = Io.Reader.fixed(plaintext);
    const put_meta = try putObjectStreaming(tmp.dir, a, .{
        .bucket = "buk",
        .key = "src-plain",
        .content_length = plaintext.len,
    }, &pr);
    defer freeMeta(a, put_meta);

    const copy_meta = try copyObject(tmp.dir, a, "buk", "src-plain", "buk", "dst-enc", null, .{
        .dst_wrap_key = &master,
    });
    defer freeMeta(a, copy_meta);

    try std.testing.expect(copy_meta.encryption != null);
    try std.testing.expectEqual(@as(u64, plaintext.len), copy_meta.size);

    const opened = try openObject(tmp.dir, a, "buk", "dst-enc");
    var file = opened.file;
    defer file.close();
    defer freeReadMeta(a, opened.meta);
    const enc = opened.meta.encryption.?;

    const wrapped_raw = try internal.decodeBase64(a, enc.wrapped_dek_b64);
    defer a.free(wrapped_raw);
    const nonce_raw = try internal.decodeBase64(a, enc.wrap_nonce_b64);
    defer a.free(nonce_raw);
    const dek = try sse.unwrapDek(&master, wrapped_raw[0..sse.wrapped_dek_len], nonce_raw[0..sse.nonce_size]);

    var read_buf: [64 * 1024]u8 = undefined;
    var fr = file.reader(&read_buf);
    var dec_writer = Io.Writer.Allocating.init(a);
    defer dec_writer.deinit();
    try sse.decryptStream(&fr.interface, &dec_writer.writer, opened.meta.size, &dek);
    try std.testing.expectEqualStrings(plaintext, dec_writer.written());
}

test "SSE-C put/get roundtrip via storage layer; wrong key fails unwrap" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try buckets.createBucket(tmp.dir, "buk");

    var customer_key: [32]u8 = undefined;
    std.crypto.random.bytes(&customer_key);
    var md5_digest: [16]u8 = undefined;
    Md5.hash(&customer_key, &md5_digest, .{});
    const b64_enc = std.base64.standard.Encoder;
    var md5_buf: [24]u8 = undefined;
    const md5_b64 = b64_enc.encode(&md5_buf, &md5_digest);

    const plaintext = "customer-managed key content, round and round." ** 20;
    var pr = Io.Reader.fixed(plaintext);
    const put_meta = try putObjectStreaming(tmp.dir, a, .{
        .bucket = "buk",
        .key = "ssec-obj",
        .content_length = plaintext.len,
        .master_key = &customer_key,
        .sse_alg = "SSE-C",
        .sse_c_key_md5 = md5_b64,
    }, &pr);
    defer freeMeta(a, put_meta);
    try std.testing.expect(put_meta.encryption != null);
    try std.testing.expectEqualStrings("SSE-C", put_meta.encryption.?.alg);

    const opened = try openObject(tmp.dir, a, "buk", "ssec-obj");
    var file = opened.file;
    defer file.close();
    defer freeReadMeta(a, opened.meta);
    const enc = opened.meta.encryption.?;
    try std.testing.expectEqualStrings(md5_b64, enc.sse_c_key_md5);

    const wrapped_raw = try internal.decodeBase64(a, enc.wrapped_dek_b64);
    defer a.free(wrapped_raw);
    const nonce_raw = try internal.decodeBase64(a, enc.wrap_nonce_b64);
    defer a.free(nonce_raw);

    // Correct customer key decrypts fine.
    const dek = try sse.unwrapDek(&customer_key, wrapped_raw[0..sse.wrapped_dek_len], nonce_raw[0..sse.nonce_size]);
    var read_buf: [64 * 1024]u8 = undefined;
    var fr = file.reader(&read_buf);
    var dec_writer = Io.Writer.Allocating.init(a);
    defer dec_writer.deinit();
    try sse.decryptStream(&fr.interface, &dec_writer.writer, opened.meta.size, &dek);
    try std.testing.expectEqualStrings(plaintext, dec_writer.written());

    // Wrong key fails to unwrap the DEK.
    var wrong_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);
    try std.testing.expectError(error.DecryptFailed, sse.unwrapDek(&wrong_key, wrapped_raw[0..sse.wrapped_dek_len], nonce_raw[0..sse.nonce_size]));
}
