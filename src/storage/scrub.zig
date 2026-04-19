//! Background bitrot scrubber.
//!
//! Periodically walks every bucket in the data directory, reads each
//! plain (non-multipart, non-encrypted) object, recomputes the MD5, and
//! compares it to the recorded ETag in the metadata sidecar.
//!
//! Multipart-composite objects (etag has a `"-N"` suffix) and SSE-encrypted
//! objects are skipped — their on-disk bytes are not the plaintext MD5.
//!
//! Failures are logged and counted via `registry.bitrot_errors_total`.
//! Successful verifications increment `registry.bitrot_ok_total`.

const std = @import("std");
const Dir = std.fs.Dir;
const Md5 = std.crypto.hash.Md5;

const paths = @import("paths.zig");
const internal = @import("internal.zig");

pub const ScrubStats = struct {
    ok: u64 = 0,
    failed: u64 = 0,
    skipped: u64 = 0,
};

/// Verify every object in `data_dir`. Returns aggregate stats.
pub fn runOnce(data_dir: Dir, allocator: std.mem.Allocator) !ScrubStats {
    var stats: ScrubStats = .{};

    var iter = data_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.startsWith(u8, entry.name, ".")) continue;

        var bucket = data_dir.openDir(entry.name, .{ .iterate = true }) catch continue;
        defer bucket.close();
        try scrubBucket(bucket, entry.name, allocator, &stats);
    }
    return stats;
}

fn scrubBucket(bd: Dir, bucket_name: []const u8, allocator: std.mem.Allocator, stats: *ScrubStats) !void {
    var walker = try bd.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.startsWith(u8, entry.path, paths.reserved_prefix)) continue;
        if (std.mem.indexOf(u8, entry.path, "/" ++ paths.reserved_prefix) != null) continue;
        if (std.mem.indexOf(u8, entry.path, "\\" ++ paths.reserved_prefix) != null) continue;

        const meta = internal.readMetadata(bd, allocator, entry.path) catch {
            stats.skipped += 1;
            continue;
        };
        defer freeMeta(allocator, meta);

        if (meta.encryption != null) {
            stats.skipped += 1;
            continue;
        }
        if (std.mem.indexOfScalar(u8, meta.etag, '-') != null) {
            // Multipart composite ETag (md5sum-of-md5s + "-N"). Skip.
            stats.skipped += 1;
            continue;
        }
        if (std.mem.eql(u8, meta.etag, "unknown")) {
            stats.skipped += 1;
            continue;
        }

        const computed = computeMd5Hex(bd, entry.path) catch {
            stats.skipped += 1;
            continue;
        };

        if (std.mem.eql(u8, &computed, meta.etag)) {
            stats.ok += 1;
        } else {
            stats.failed += 1;
            std.log.warn(
                "bitrot: bucket={s} key={s} expected_etag={s} computed={s}",
                .{ bucket_name, entry.path, meta.etag, &computed },
            );
        }
    }
}

fn freeMeta(allocator: std.mem.Allocator, meta: anytype) void {
    allocator.free(meta.content_type);
    allocator.free(meta.etag);
    if (meta.encryption) |enc| {
        allocator.free(enc.alg);
        allocator.free(enc.wrapped_dek_b64);
        allocator.free(enc.wrap_nonce_b64);
    }
}

fn computeMd5Hex(bd: Dir, sub_path: []const u8) ![32]u8 {
    var f = try bd.openFile(sub_path, .{});
    defer f.close();
    var md5 = Md5.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        md5.update(buf[0..n]);
    }
    var digest: [16]u8 = undefined;
    md5.final(&digest);
    var hex: [32]u8 = undefined;
    const charset = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        hex[i * 2] = charset[b >> 4];
        hex[i * 2 + 1] = charset[b & 0xF];
    }
    return hex;
}

test "scrub clean bucket reports ok" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    const objects = @import("objects.zig");
    try buckets.createBucket(tmp.dir, "scrub-bucket");

    var fbs = std.Io.Reader.fixed("hello world");
    const meta = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "scrub-bucket",
        .key = "obj.txt",
        .content_length = 11,
        .content_type = "text/plain",
    }, &fbs);
    freeMeta(allocator, meta);

    const stats = try runOnce(tmp.dir, allocator);
    try std.testing.expectEqual(@as(u64, 1), stats.ok);
    try std.testing.expectEqual(@as(u64, 0), stats.failed);
}

test "scrub detects tampered file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("buckets.zig");
    const objects = @import("objects.zig");
    try buckets.createBucket(tmp.dir, "scrub-bucket");

    var fbs = std.Io.Reader.fixed("good content");
    const meta = try objects.putObjectStreaming(tmp.dir, allocator, .{
        .bucket = "scrub-bucket",
        .key = "obj.txt",
        .content_length = 12,
        .content_type = "text/plain",
    }, &fbs);
    freeMeta(allocator, meta);

    // Tamper.
    var bd = try tmp.dir.openDir("scrub-bucket", .{});
    defer bd.close();
    try bd.writeFile(.{ .sub_path = "obj.txt", .data = "BAD CONTENT!" });

    const stats = try runOnce(tmp.dir, allocator);
    try std.testing.expectEqual(@as(u64, 1), stats.failed);
}
