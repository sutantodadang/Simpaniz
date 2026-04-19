const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const util = @import("../util.zig");
const paths = @import("paths.zig");
const types = @import("types.zig");
const Error = types.Error;
const BucketSummary = types.BucketSummary;

pub fn createBucket(data_dir: Dir, name: []const u8) Error!void {
    util.validateBucketName(name) catch return error.InvalidKey;
    data_dir.makeDir(name) catch |err| switch (err) {
        error.PathAlreadyExists => return error.BucketAlreadyExists,
        else => return error.Internal,
    };
    var bd = data_dir.openDir(name, .{}) catch return error.Internal;
    defer bd.close();
    bd.makeDir(paths.meta_dir) catch {};
    bd.makeDir(paths.mp_dir) catch {};
    bd.makeDir(paths.tmp_dir) catch {};
    bd.makeDir(paths.tags_dir) catch {};
}

pub fn deleteBucket(data_dir: Dir, name: []const u8) Error!void {
    util.validateBucketName(name) catch return error.InvalidKey;
    {
        var bd = data_dir.openDir(name, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return error.BucketNotFound,
            else => return error.Internal,
        };
        defer bd.close();

        var iter = bd.iterate();
        while (iter.next() catch return error.Internal) |entry| {
            if (std.mem.startsWith(u8, entry.name, paths.reserved_prefix)) continue;
            return error.BucketNotEmpty;
        }
        bd.deleteTree(paths.meta_dir) catch {};
        bd.deleteTree(paths.mp_dir) catch {};
        bd.deleteTree(paths.tmp_dir) catch {};
        bd.deleteTree(paths.tags_dir) catch {};
        bd.deleteFile(paths.policy_file) catch {};
    }
    data_dir.deleteDir(name) catch return error.Internal;
}

pub fn bucketExists(data_dir: Dir, name: []const u8) bool {
    util.validateBucketName(name) catch return false;
    data_dir.access(name, .{}) catch return false;
    return true;
}

pub fn listBuckets(data_dir: Dir, allocator: Allocator) Error![]BucketSummary {
    var list = std.ArrayList(BucketSummary){};
    errdefer {
        for (list.items) |b| allocator.free(b.name);
        list.deinit(allocator);
    }

    var iter = data_dir.iterate();
    while (iter.next() catch return error.Internal) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.startsWith(u8, entry.name, ".")) continue;

        const name_copy = allocator.dupe(u8, entry.name) catch return error.OutOfMemory;
        const stat = data_dir.statFile(entry.name) catch {
            list.append(allocator, .{ .name = name_copy, .creation_ns = 0 }) catch return error.OutOfMemory;
            continue;
        };
        list.append(allocator, .{ .name = name_copy, .creation_ns = stat.ctime }) catch return error.OutOfMemory;
    }
    return list.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

test "bucket lifecycle" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try createBucket(tmp.dir, "test-bucket");
    try std.testing.expect(bucketExists(tmp.dir, "test-bucket"));
    try std.testing.expectError(error.BucketAlreadyExists, createBucket(tmp.dir, "test-bucket"));
    try deleteBucket(tmp.dir, "test-bucket");
    try std.testing.expect(!bucketExists(tmp.dir, "test-bucket"));
}

test "createBucket rejects bad name" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try std.testing.expectError(error.InvalidKey, createBucket(tmp.dir, "Bad_Name"));
}

test "listBuckets is repeatable on the same dir handle" {
    // Regression: we used to call iterateAssumeFirstIteration on the
    // long-lived server data_dir handle. The first listBuckets returned
    // results, every subsequent call returned an empty slice because the
    // directory cursor had already been exhausted. Use iterate() so each
    // call gets a fresh, rewound iterator.
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try createBucket(tmp.dir, "alpha");
    try createBucket(tmp.dir, "beta");
    const a = std.testing.allocator;

    const first = try listBuckets(tmp.dir, a);
    defer { for (first) |b| a.free(b.name); a.free(first); }
    try std.testing.expectEqual(@as(usize, 2), first.len);

    const second = try listBuckets(tmp.dir, a);
    defer { for (second) |b| a.free(b.name); a.free(second); }
    try std.testing.expectEqual(@as(usize, 2), second.len);
}
