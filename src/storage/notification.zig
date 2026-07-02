//! Bucket event notification configuration storage.
//!
//! The config is stored verbatim as XML at `<bucket>/.simpaniz-notify.xml`.
//! There is no delete endpoint — PUTting an empty (or event-less) config
//! functionally clears notifications, since `events.Notifier.fire` treats a
//! config with no matching `<Event>` entries as "nothing to send".
const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

const paths = @import("paths.zig");
const types = @import("types.zig");
const Error = types.Error;

pub fn putBucketNotification(data_dir: Dir, bucket: []const u8, xml_body: []const u8) Error!void {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    bd.writeFile(.{ .sub_path = paths.notify_file, .data = xml_body }) catch return error.Internal;
}

pub fn getBucketNotification(data_dir: Dir, allocator: Allocator, bucket: []const u8) Error!?[]u8 {
    var bd = data_dir.openDir(bucket, .{}) catch return error.BucketNotFound;
    defer bd.close();
    var buf: [64 * 1024]u8 = undefined;
    const data = bd.readFile(paths.notify_file, &buf) catch return null;
    return allocator.dupe(u8, data) catch error.OutOfMemory;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "putBucketNotification + getBucketNotification roundtrip" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");

    const xml_body = "<NotificationConfiguration><Event>s3:ObjectCreated:*</Event></NotificationConfiguration>";
    try putBucketNotification(tmp.dir, "b", xml_body);

    const got = try getBucketNotification(tmp.dir, a, "b");
    defer if (got) |g| a.free(g);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(xml_body, got.?);
}

test "getBucketNotification missing config returns null" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("b");

    const got = try getBucketNotification(tmp.dir, a, "b");
    try std.testing.expect(got == null);
}

test "getBucketNotification missing bucket errors" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.BucketNotFound, getBucketNotification(tmp.dir, a, "nope"));
}
