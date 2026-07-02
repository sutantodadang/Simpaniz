//! Default bucket encryption configuration ("apply SSE to every PUT unless
//! the request overrides it"). Stored verbatim as XML at
//! `<bucket>/.simpaniz-encryption.xml`, mirroring policy.zig's pattern.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const paths = @import("paths.zig");
const types = @import("types.zig");
const Error = types.Error;

pub fn putBucketEncryption(data_dir: Dir, bucket: []const u8, xml_body: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.writeFile(.{ .sub_path = paths.encryption_file, .data = xml_body }) catch return error.Internal;
}

pub fn getBucketEncryption(data_dir: Dir, allocator: Allocator, bucket: []const u8) Error!?[]u8 {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    var buf: [4096]u8 = undefined;
    const data = bd.readFile(paths.encryption_file, &buf) catch return null;
    return allocator.dupe(u8, data) catch error.OutOfMemory;
}

pub fn deleteBucketEncryption(data_dir: Dir, bucket: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.deleteFile(paths.encryption_file) catch {};
}

pub const Alg = enum { aes256, aws_kms };

/// Reads `<bucket>/.simpaniz-encryption.xml` (into caller-provided `buf`; 4KB
/// is plenty) and returns the configured default SSE algorithm, or null when
/// unset/missing/unrecognized.
pub fn defaultAlgorithm(data_dir: Dir, bucket: []const u8, buf: []u8) ?Alg {
    var bd = data_dir.openDir(bucket, .{}) catch return null;
    defer bd.close();
    const data = bd.readFile(paths.encryption_file, buf) catch return null;
    if (std.mem.indexOf(u8, data, "<SSEAlgorithm>AES256</SSEAlgorithm>") != null) return .aes256;
    if (std.mem.indexOf(u8, data, "<SSEAlgorithm>aws:kms</SSEAlgorithm>") != null) return .aws_kms;
    return null;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "putBucketEncryption + getBucketEncryption roundtrip" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");

    const xml_body = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    try putBucketEncryption(tmp.dir, "b", xml_body);

    const got = try getBucketEncryption(tmp.dir, a, "b");
    defer if (got) |g| a.free(g);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(xml_body, got.?);
}

test "getBucketEncryption missing config returns null" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");

    const got = try getBucketEncryption(tmp.dir, a, "b");
    try std.testing.expect(got == null);
}

test "defaultAlgorithm AES256" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");
    try putBucketEncryption(tmp.dir, "b", "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>");
    var buf: [4096]u8 = undefined;
    try std.testing.expectEqual(Alg.aes256, defaultAlgorithm(tmp.dir, "b", &buf).?);
}

test "defaultAlgorithm aws:kms" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");
    try putBucketEncryption(tmp.dir, "b", "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>");
    var buf: [4096]u8 = undefined;
    try std.testing.expectEqual(Alg.aws_kms, defaultAlgorithm(tmp.dir, "b", &buf).?);
}

test "defaultAlgorithm missing config returns null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");
    var buf: [4096]u8 = undefined;
    try std.testing.expect(defaultAlgorithm(tmp.dir, "b", &buf) == null);
}
