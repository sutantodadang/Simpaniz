const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const Io = std.Io;
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../util.zig");
const xml = @import("../xml.zig");
const paths = @import("paths.zig");
const types = @import("types.zig");
const internal = @import("internal.zig");

const Error = types.Error;
const ObjectMeta = types.ObjectMeta;
const PartCopyRange = types.PartCopyRange;

pub fn createUpload(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8, content_type: []const u8) Error![]const u8 {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();

    var rand_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var upload_hex: [32]u8 = undefined;
    util.hexEncodeBuf(&rand_bytes, &upload_hex);
    const upload_id = allocator.dupe(u8, upload_hex[0 .. rand_bytes.len * 2]) catch return error.OutOfMemory;
    errdefer allocator.free(upload_id);

    const upload_root = std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(upload_root);
    bd.makePath(upload_root) catch return error.Internal;
    const parts_root = std.fmt.allocPrint(allocator, "{s}/parts", .{upload_root}) catch return error.OutOfMemory;
    defer allocator.free(parts_root);
    bd.makePath(parts_root) catch return error.Internal;

    const meta_path = std.fmt.allocPrint(allocator, "{s}/meta.json", .{upload_root}) catch return error.OutOfMemory;
    defer allocator.free(meta_path);
    const meta_json = std.fmt.allocPrint(allocator,
        "{{\"key\":\"{s}\",\"content_type\":\"{s}\"}}", .{ key, content_type }) catch return error.OutOfMemory;
    defer allocator.free(meta_json);
    bd.writeFile(.{ .sub_path = meta_path, .data = meta_json }) catch return error.Internal;

    return upload_id;
}

pub fn putPart(
    data_dir: Dir,
    allocator: Allocator,
    bucket: []const u8,
    upload_id: []const u8,
    part_number: u32,
    content_length: u64,
    body_reader: *Io.Reader,
) Error![]const u8 {
    if (part_number == 0 or part_number > 10_000) return error.InvalidPart;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    try internal.ensureUploadExists(bd, allocator, upload_id);

    const part_path = std.fmt.allocPrint(allocator, "{s}/{s}/parts/{d}", .{ paths.mp_dir, upload_id, part_number }) catch return error.OutOfMemory;
    defer allocator.free(part_path);

    var f = bd.createFile(part_path, .{ .truncate = true }) catch return error.Internal;
    defer f.close();
    var wbuf: [64 * 1024]u8 = undefined;
    var fw = f.writer(&wbuf);
    var md5 = Md5.init(.{});
    var sha = Sha256.init(.{});
    const written = internal.streamWithDigest(body_reader, &fw.interface, content_length, &md5, &sha) catch return error.Internal;
    fw.interface.flush() catch return error.Internal;
    f.sync() catch {};
    if (written != content_length) return error.BadDigest;

    var d: [16]u8 = undefined;
    md5.final(&d);
    const hex = util.hexEncodeMd5(d);
    return allocator.dupe(u8, &hex) catch error.OutOfMemory;
}

pub fn completeUpload(
    data_dir: Dir,
    allocator: Allocator,
    bucket: []const u8,
    upload_id: []const u8,
    part_numbers: []const u32,
) Error!ObjectMeta {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    try internal.ensureUploadExists(bd, allocator, upload_id);

    const meta_path = std.fmt.allocPrint(allocator, "{s}/{s}/meta.json", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(meta_path);
    var meta_buf: [4096]u8 = undefined;
    const meta_json = bd.readFile(meta_path, &meta_buf) catch return error.UploadNotFound;
    const key = (internal.extractJson(meta_json, "key") orelse return error.UploadNotFound);
    const ct = internal.extractJson(meta_json, "content_type") orelse "application/octet-stream";
    const key_owned = allocator.dupe(u8, key) catch return error.OutOfMemory;
    defer allocator.free(key_owned);
    const ct_owned = allocator.dupe(u8, ct) catch return error.OutOfMemory;
    defer allocator.free(ct_owned);

    if (std.fs.path.dirname(key_owned)) |parent| bd.makePath(parent) catch {};

    var rand_bytes: [12]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var tmp_name_buf: [64]u8 = undefined;
    var hex_buf2: [24]u8 = undefined;
    util.hexEncodeBuf(&rand_bytes, &hex_buf2);
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}/complete-{s}", .{ paths.tmp_dir, hex_buf2[0 .. rand_bytes.len * 2] }) catch return error.Internal;

    var out_file = bd.createFile(tmp_name, .{ .truncate = true, .exclusive = true }) catch return error.Internal;
    var wbuf: [64 * 1024]u8 = undefined;
    var fw = out_file.writer(&wbuf);

    var part_md5_concat = std.ArrayList(u8){};
    defer part_md5_concat.deinit(allocator);

    var total: u64 = 0;
    for (part_numbers) |pn| {
        if (pn == 0 or pn > 10_000) {
            out_file.close();
            bd.deleteFile(tmp_name) catch {};
            return error.InvalidPart;
        }
        const part_path = std.fmt.allocPrint(allocator, "{s}/{s}/parts/{d}", .{ paths.mp_dir, upload_id, pn }) catch return error.OutOfMemory;
        defer allocator.free(part_path);
        var pf = bd.openFile(part_path, .{}) catch {
            out_file.close();
            bd.deleteFile(tmp_name) catch {};
            return error.InvalidPart;
        };
        defer pf.close();
        const pstat = pf.stat() catch {
            out_file.close();
            bd.deleteFile(tmp_name) catch {};
            return error.Internal;
        };

        var pbuf: [64 * 1024]u8 = undefined;
        var pr = pf.reader(&pbuf);
        var pmd5 = Md5.init(.{});
        var psha = Sha256.init(.{});
        _ = internal.streamWithDigest(&pr.interface, &fw.interface, pstat.size, &pmd5, &psha) catch {
            out_file.close();
            bd.deleteFile(tmp_name) catch {};
            return error.Internal;
        };
        var pd: [16]u8 = undefined;
        pmd5.final(&pd);
        part_md5_concat.appendSlice(allocator, &pd) catch return error.OutOfMemory;
        total += pstat.size;
    }
    fw.interface.flush() catch {
        out_file.close();
        bd.deleteFile(tmp_name) catch {};
        return error.Internal;
    };
    out_file.sync() catch {};
    out_file.close();

    bd.rename(tmp_name, key_owned) catch {
        bd.deleteFile(tmp_name) catch {};
        return error.Internal;
    };

    var final_md5: [16]u8 = undefined;
    Md5.hash(part_md5_concat.items, &final_md5, .{});
    const final_hex = util.hexEncodeMd5(final_md5);
    const etag_str = std.fmt.allocPrint(allocator, "{s}-{d}", .{ &final_hex, part_numbers.len }) catch return error.OutOfMemory;

    try internal.writeMetadata(bd, allocator, key_owned, .{
        .content_type = ct_owned,
        .etag = etag_str,
        .size = total,
        .mtime_ns = std.time.nanoTimestamp(),
    });

    const upload_root = std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(upload_root);
    bd.deleteTree(upload_root) catch {};

    const final_stat = bd.statFile(key_owned) catch return error.Internal;
    return .{
        .content_type = allocator.dupe(u8, ct_owned) catch return error.OutOfMemory,
        .etag = etag_str,
        .size = final_stat.size,
        .mtime_ns = final_stat.mtime,
    };
}

pub fn abortUpload(data_dir: Dir, allocator: Allocator, bucket: []const u8, upload_id: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    const upload_root = std.fmt.allocPrint(allocator, "{s}/{s}", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(upload_root);
    bd.deleteTree(upload_root) catch return error.UploadNotFound;
}

pub fn listParts(data_dir: Dir, allocator: Allocator, bucket: []const u8, upload_id: []const u8) Error![]xml.PartInfo {
    var bd = data_dir.openDir(bucket, .{ .iterate = true }) catch return error.BucketNotFound;
    defer bd.close();
    const parts_path = std.fmt.allocPrint(allocator, "{s}/{s}/parts", .{ paths.mp_dir, upload_id }) catch return error.OutOfMemory;
    defer allocator.free(parts_path);
    var pd = bd.openDir(parts_path, .{ .iterate = true }) catch return error.UploadNotFound;
    defer pd.close();

    var list = std.ArrayList(xml.PartInfo){};
    errdefer {
        for (list.items) |p| {
            allocator.free(p.etag);
            allocator.free(p.last_modified);
        }
        list.deinit(allocator);
    }

    var iter = pd.iterate();
    while (iter.next() catch return error.Internal) |entry| {
        if (entry.kind != .file) continue;
        const pn = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        const stat = pd.statFile(entry.name) catch continue;

        var f = pd.openFile(entry.name, .{}) catch continue;
        defer f.close();
        var rbuf: [64 * 1024]u8 = undefined;
        var fr = f.reader(&rbuf);
        var md5 = Md5.init(.{});
        var tmp_buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = fr.interface.readSliceShort(&tmp_buf) catch 0;
            if (n == 0) break;
            md5.update(tmp_buf[0..n]);
        }
        var d: [16]u8 = undefined;
        md5.final(&d);
        const hex = util.hexEncodeMd5(d);
        const etag = std.fmt.allocPrint(allocator, "\"{s}\"", .{&hex}) catch return error.OutOfMemory;
        var lm_buf: [32]u8 = undefined;
        const lm = util.formatIso8601(&lm_buf, stat.mtime);
        const lm_owned = allocator.dupe(u8, lm) catch return error.OutOfMemory;
        list.append(allocator, .{ .part_number = pn, .etag = etag, .size = stat.size, .last_modified = lm_owned }) catch return error.OutOfMemory;
    }
    std.mem.sort(xml.PartInfo, list.items, {}, struct {
        fn lt(_: void, a: xml.PartInfo, b: xml.PartInfo) bool {
            return a.part_number < b.part_number;
        }
    }.lt);
    return list.toOwnedSlice(allocator) catch error.OutOfMemory;
}

/// Walk `.simpaniz-mp/` and return one entry per active upload.
pub fn listMultipartUploads(data_dir: Dir, allocator: Allocator, bucket: []const u8) Error![]xml.InProgressUpload {
    var bd = data_dir.openDir(bucket, .{ .iterate = true }) catch return error.BucketNotFound;
    defer bd.close();
    var mp_d = bd.openDir(paths.mp_dir, .{ .iterate = true }) catch {
        return allocator.alloc(xml.InProgressUpload, 0) catch error.OutOfMemory;
    };
    defer mp_d.close();

    var list = std.ArrayList(xml.InProgressUpload){};
    errdefer {
        for (list.items) |u| {
            allocator.free(u.key);
            allocator.free(u.upload_id);
            allocator.free(u.initiated);
        }
        list.deinit(allocator);
    }

    var iter = mp_d.iterate();
    while (iter.next() catch return error.Internal) |entry| {
        if (entry.kind != .directory) continue;
        const upload_id = allocator.dupe(u8, entry.name) catch return error.OutOfMemory;
        errdefer allocator.free(upload_id);

        const meta_path = std.fmt.allocPrint(allocator, "{s}/meta.json", .{entry.name}) catch return error.OutOfMemory;
        defer allocator.free(meta_path);
        var mbuf: [4096]u8 = undefined;
        const mjson = mp_d.readFile(meta_path, &mbuf) catch continue;
        const k = internal.extractJson(mjson, "key") orelse continue;
        const key_owned = allocator.dupe(u8, k) catch return error.OutOfMemory;
        errdefer allocator.free(key_owned);

        const stat = mp_d.statFile(meta_path) catch continue;
        var lm_buf: [32]u8 = undefined;
        const lm = util.formatIso8601(&lm_buf, stat.mtime);
        const lm_owned = allocator.dupe(u8, lm) catch return error.OutOfMemory;

        list.append(allocator, .{ .key = key_owned, .upload_id = upload_id, .initiated = lm_owned }) catch return error.OutOfMemory;
    }
    return list.toOwnedSlice(allocator) catch error.OutOfMemory;
}

/// UploadPartCopy: read bytes from `src_bucket/src_key` (optionally limited
/// to `range`) and write them as part `part_number` of `upload_id`.
pub fn uploadPartCopy(
    data_dir: Dir,
    allocator: Allocator,
    src_bucket: []const u8,
    src_key: []const u8,
    dst_bucket: []const u8,
    upload_id: []const u8,
    part_number: u32,
    range: ?PartCopyRange,
) Error!struct { etag: []const u8, last_modified: []const u8 } {
    if (part_number == 0 or part_number > 10_000) return error.InvalidPart;
    util.validateObjectKey(src_key) catch return error.InvalidKey;

    var src_bd = data_dir.openDir(src_bucket, .{}) catch return error.BucketNotFound;
    defer src_bd.close();
    var src_file = src_bd.openFile(src_key, .{}) catch return error.ObjectNotFound;
    defer src_file.close();
    const src_stat = src_file.stat() catch return error.Internal;

    var start: u64 = 0;
    var length: u64 = src_stat.size;
    if (range) |r| {
        if (r.start >= src_stat.size or r.end >= src_stat.size or r.start > r.end) return error.InvalidPart;
        start = r.start;
        length = r.end - r.start + 1;
    }
    src_file.seekTo(start) catch return error.Internal;

    var dst_bd = data_dir.openDir(dst_bucket, .{}) catch return error.BucketNotFound;
    defer dst_bd.close();
    try internal.ensureUploadExists(dst_bd, allocator, upload_id);

    const part_path = std.fmt.allocPrint(allocator, "{s}/{s}/parts/{d}", .{ paths.mp_dir, upload_id, part_number }) catch return error.OutOfMemory;
    defer allocator.free(part_path);

    var out = dst_bd.createFile(part_path, .{ .truncate = true }) catch return error.Internal;
    defer out.close();
    var wbuf: [64 * 1024]u8 = undefined;
    var fw = out.writer(&wbuf);
    var md5 = Md5.init(.{});

    var copy_buf: [64 * 1024]u8 = undefined;
    var remaining = length;
    while (remaining > 0) {
        const want: usize = @intCast(@min(@as(u64, copy_buf.len), remaining));
        const got = src_file.read(copy_buf[0..want]) catch return error.Internal;
        if (got == 0) return error.BadDigest;
        md5.update(copy_buf[0..got]);
        fw.interface.writeAll(copy_buf[0..got]) catch return error.Internal;
        remaining -= @intCast(got);
    }
    fw.interface.flush() catch return error.Internal;
    out.sync() catch {};

    var d: [16]u8 = undefined;
    md5.final(&d);
    const hex = util.hexEncodeMd5(d);
    const etag = allocator.dupe(u8, &hex) catch return error.OutOfMemory;
    var lm_buf: [32]u8 = undefined;
    const lm = util.formatIso8601(&lm_buf, std.time.nanoTimestamp());
    const lm_owned = allocator.dupe(u8, lm) catch return error.OutOfMemory;
    return .{ .etag = etag, .last_modified = lm_owned };
}
