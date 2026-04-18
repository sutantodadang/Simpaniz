const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const paths = @import("paths.zig");
const types = @import("types.zig");
const Error = types.Error;

pub fn putBucketPolicy(data_dir: Dir, bucket: []const u8, json_body: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.writeFile(.{ .sub_path = paths.policy_file, .data = json_body }) catch return error.Internal;
}

pub fn getBucketPolicy(data_dir: Dir, allocator: Allocator, bucket: []const u8) Error!?[]u8 {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    var buf: [64 * 1024]u8 = undefined;
    const data = bd.readFile(paths.policy_file, &buf) catch return null;
    return allocator.dupe(u8, data) catch error.OutOfMemory;
}

pub fn deleteBucketPolicy(data_dir: Dir, bucket: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.deleteFile(paths.policy_file) catch {};
}
