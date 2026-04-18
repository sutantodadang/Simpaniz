const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const util = @import("../util.zig");
const paths = @import("paths.zig");
const types = @import("types.zig");
const internal = @import("internal.zig");
const Error = types.Error;

/// Replace the tag set for an object. Body is the raw XML the client sent
/// (we store it verbatim so GET can echo it back). The object must exist.
pub fn putObjectTagging(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8, xml_body: []const u8) Error!void {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.access(key, .{}) catch return error.ObjectNotFound;
    const tags_path = std.fmt.allocPrint(allocator, "{s}/{s}.xml", .{ paths.tags_dir, key }) catch return error.OutOfMemory;
    defer allocator.free(tags_path);
    if (std.fs.path.dirname(tags_path)) |parent| bd.makePath(parent) catch {};
    bd.writeFile(.{ .sub_path = tags_path, .data = xml_body }) catch return error.Internal;
}

/// Return the stored tag XML body (caller-owned). If no tags are set,
/// returns an empty `<Tagging><TagSet/></Tagging>` document.
pub fn getObjectTagging(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8) Error![]u8 {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.access(key, .{}) catch return error.ObjectNotFound;
    const tags_path = std.fmt.allocPrint(allocator, "{s}/{s}.xml", .{ paths.tags_dir, key }) catch return error.OutOfMemory;
    defer allocator.free(tags_path);
    var buf: [64 * 1024]u8 = undefined;
    const data = bd.readFile(tags_path, &buf) catch {
        return allocator.dupe(u8, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet/></Tagging>") catch error.OutOfMemory;
    };
    return allocator.dupe(u8, data) catch error.OutOfMemory;
}

pub fn deleteObjectTagging(data_dir: Dir, allocator: Allocator, bucket: []const u8, key: []const u8) Error!void {
    util.validateObjectKey(key) catch return error.InvalidKey;
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.access(key, .{}) catch return error.ObjectNotFound;
    const tags_path = std.fmt.allocPrint(allocator, "{s}/{s}.xml", .{ paths.tags_dir, key }) catch return error.OutOfMemory;
    defer allocator.free(tags_path);
    bd.deleteFile(tags_path) catch {};
    internal.pruneEmptyParents(bd, tags_path);
}
