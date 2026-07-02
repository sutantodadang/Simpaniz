//! S3 event notifications — webhook target.
//!
//! Bucket notification configuration is stored as
//! `<bucket>/.simpaniz-notify.xml` (see `storage/notification.zig`):
//!
//!     <NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
//!       <Event>s3:ObjectCreated:*</Event>
//!       <Event>s3:ObjectRemoved:*</Event>
//!       <Filter>
//!         <S3Key>
//!           <FilterRule><Name>prefix</Name><Value>images/</Value></FilterRule>
//!           <FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule>
//!         </S3Key>
//!       </Filter>
//!     </NotificationConfiguration>
//!
//! On a successful object mutation, handlers call `Notifier.fire` with the
//! event details. `fire` cheaply checks the bucket's notification config
//! (no config file → drop) before enqueuing anything, so buckets without
//! notifications configured pay near-zero cost. Matched events are handed
//! off to a background worker thread that POSTs an S3-event-shaped JSON
//! payload to the configured webhook URL — best-effort, no retries (v1).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const storage = @import("storage.zig");
const xml = @import("xml.zig");
const util = @import("util.zig");

// ── Types ────────────────────────────────────────────────────────────────────

pub const EventName = enum {
    created_put,
    created_copy,
    created_complete_multipart,
    removed_delete,
    removed_delete_marker,

    pub fn s3Name(self: EventName) []const u8 {
        return switch (self) {
            .created_put => "s3:ObjectCreated:Put",
            .created_copy => "s3:ObjectCreated:Copy",
            .created_complete_multipart => "s3:ObjectCreated:CompleteMultipartUpload",
            .removed_delete => "s3:ObjectRemoved:Delete",
            .removed_delete_marker => "s3:ObjectRemoved:DeleteMarkerCreated",
        };
    }
};

pub const Event = struct {
    bucket: []const u8,
    key: []const u8,
    name: EventName,
    size: u64,
    etag: []const u8,
};

const Task = struct {
    bucket: []u8, // owned
    key: []u8, // owned
    name: EventName,
    size: u64,
    etag: []u8, // owned
};

// ── Notifier ─────────────────────────────────────────────────────────────────

pub const Notifier = struct {
    allocator: Allocator,
    webhook_url: []const u8, // owned
    region: []const u8, // owned
    data_dir: std.fs.Dir,
    queue: std.ArrayList(Task),
    mutex: Thread.Mutex = .{},
    cond: Thread.Condition = .{},
    worker: ?Thread = null,
    running: std.atomic.Value(bool) = .{ .raw = false },

    pub fn init(allocator: Allocator, webhook_url: []const u8, region: []const u8, data_dir: std.fs.Dir) !*Notifier {
        const n = try allocator.create(Notifier);
        errdefer allocator.destroy(n);
        n.* = .{
            .allocator = allocator,
            .webhook_url = try allocator.dupe(u8, webhook_url),
            .region = try allocator.dupe(u8, region),
            .data_dir = data_dir,
            .queue = std.ArrayList(Task){},
        };
        return n;
    }

    pub fn start(self: *Notifier) !void {
        if (self.worker != null) return;
        self.running.store(true, .seq_cst);
        self.worker = try Thread.spawn(.{}, workerLoop, .{self});
    }

    /// Signal the worker to stop and join it. Safe to call more than once.
    pub fn shutdown(self: *Notifier) void {
        self.running.store(false, .seq_cst);
        self.mutex.lock();
        self.cond.broadcast();
        self.mutex.unlock();
        if (self.worker) |w| {
            w.join();
            self.worker = null;
        }
    }

    pub fn deinit(self: *Notifier) void {
        self.shutdown();
        for (self.queue.items) |t| {
            self.allocator.free(t.bucket);
            self.allocator.free(t.key);
            self.allocator.free(t.etag);
        }
        self.queue.deinit(self.allocator);
        self.allocator.free(self.webhook_url);
        self.allocator.free(self.region);
        self.allocator.destroy(self);
    }

    /// Check the bucket's notification config and, on a match, enqueue the
    /// event for async delivery. Never fails the caller's request path —
    /// all errors are swallowed (logged at warn where useful).
    pub fn fire(self: *Notifier, ev: Event) void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const cfg_text = storage.getBucketNotification(self.data_dir, a, ev.bucket) catch return;
        const text = cfg_text orelse return; // no config — drop

        if (!configAllows(a, text, ev.name.s3Name(), ev.key)) return;

        const bucket_dup = self.allocator.dupe(u8, ev.bucket) catch return;
        const key_dup = self.allocator.dupe(u8, ev.key) catch {
            self.allocator.free(bucket_dup);
            return;
        };
        const etag_dup = self.allocator.dupe(u8, ev.etag) catch {
            self.allocator.free(bucket_dup);
            self.allocator.free(key_dup);
            return;
        };

        const task = Task{ .bucket = bucket_dup, .key = key_dup, .name = ev.name, .size = ev.size, .etag = etag_dup };

        self.mutex.lock();
        self.queue.append(self.allocator, task) catch {
            self.mutex.unlock();
            self.allocator.free(bucket_dup);
            self.allocator.free(key_dup);
            self.allocator.free(etag_dup);
            return;
        };
        self.mutex.unlock();
        self.cond.signal();
    }

    fn workerLoop(self: *Notifier) void {
        while (self.running.load(.seq_cst)) {
            const maybe = self.popNext();
            if (maybe) |task| {
                self.process(task);
            } else {
                self.mutex.lock();
                if (self.queue.items.len == 0 and self.running.load(.seq_cst)) {
                    self.cond.timedWait(&self.mutex, 500 * std.time.ns_per_ms) catch {};
                }
                self.mutex.unlock();
            }
        }
    }

    fn popNext(self: *Notifier) ?Task {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }

    /// Best-effort delivery to the webhook. No retries (v1) — a failed
    /// delivery is logged and dropped.
    fn process(self: *Notifier, task_in: Task) void {
        const task = task_in;
        defer {
            self.allocator.free(task.bucket);
            self.allocator.free(task.key);
            self.allocator.free(task.etag);
        }

        var time_buf: [32]u8 = undefined;
        const time_iso = util.formatIso8601(&time_buf, std.time.nanoTimestamp());

        const payload = buildPayload(self.allocator, self.region, task, time_iso) catch |e| {
            std.log.warn("events: failed to build payload: {any}", .{e});
            return;
        };
        defer self.allocator.free(payload);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = self.webhook_url },
            .method = .POST,
            .payload = payload,
            .headers = .{ .content_type = .{ .override = "application/json" } },
            .keep_alive = false,
        }) catch |e| {
            std.log.warn("events: webhook delivery failed: {any}", .{e});
            return;
        };

        const code = @intFromEnum(result.status);
        if (code < 200 or code >= 300) {
            std.log.warn("events: webhook returned status {d}", .{code});
        }
    }
};

// ── Config matching (pure, testable without HTTP) ───────────────────────────

/// True if `xml_text` (a bucket's `.simpaniz-notify.xml` contents) has at
/// least one `<Event>` pattern matching `event_name`, and any configured
/// prefix/suffix FilterRules also match `key`.
fn configAllows(allocator: Allocator, xml_text: []const u8, event_name: []const u8, key: []const u8) bool {
    const events_list = xml.collectTagValues(allocator, xml_text, "Event") catch return false;
    defer allocator.free(events_list);
    if (events_list.len == 0) return false;

    var matched = false;
    for (events_list) |pattern| {
        if (eventPatternMatch(pattern, event_name)) {
            matched = true;
            break;
        }
    }
    if (!matched) return false;

    const names = xml.collectTagValues(allocator, xml_text, "Name") catch return true;
    defer allocator.free(names);
    const values = xml.collectTagValues(allocator, xml_text, "Value") catch return true;
    defer allocator.free(values);
    const n = @min(names.len, values.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const rule_name = names[i];
        const rule_value = values[i];
        if (std.ascii.eqlIgnoreCase(rule_name, "prefix")) {
            if (!std.mem.startsWith(u8, key, rule_value)) return false;
        } else if (std.ascii.eqlIgnoreCase(rule_name, "suffix")) {
            if (!std.mem.endsWith(u8, key, rule_value)) return false;
        }
    }
    return true;
}

/// `pattern` matches `name` exactly, or as a prefix when `pattern` ends
/// with `*` (e.g. "s3:ObjectCreated:*" matches "s3:ObjectCreated:Put").
fn eventPatternMatch(pattern: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, pattern, name)) return true;
    if (std.mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, name, prefix);
    }
    return false;
}

// ── JSON payload ─────────────────────────────────────────────────────────────

fn jsonEscapeAlloc(allocator: Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(allocator);
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            else => try out.append(allocator, c),
        }
    }
    return out.toOwnedSlice(allocator);
}

fn buildPayload(allocator: Allocator, region: []const u8, task: Task, time_iso: []const u8) ![]u8 {
    const bucket_esc = try jsonEscapeAlloc(allocator, task.bucket);
    defer allocator.free(bucket_esc);
    const key_esc = try jsonEscapeAlloc(allocator, task.key);
    defer allocator.free(key_esc);
    const etag_esc = try jsonEscapeAlloc(allocator, task.etag);
    defer allocator.free(etag_esc);

    return std.fmt.allocPrint(allocator,
        \\{{"Records":[{{"eventVersion":"2.1","eventSource":"simpaniz:s3","awsRegion":"{s}","eventTime":"{s}","eventName":"{s}","s3":{{"s3SchemaVersion":"1.0","bucket":{{"name":"{s}","arn":"arn:aws:s3:::{s}"}},"object":{{"key":"{s}","size":{d},"eTag":"{s}"}}}}}}]}}
    , .{ region, time_iso, task.name.s3Name(), bucket_esc, bucket_esc, key_esc, task.size, etag_esc });
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "eventPatternMatch exact" {
    try std.testing.expect(eventPatternMatch("s3:ObjectCreated:Put", "s3:ObjectCreated:Put"));
    try std.testing.expect(!eventPatternMatch("s3:ObjectCreated:Put", "s3:ObjectCreated:Copy"));
}

test "eventPatternMatch wildcard" {
    try std.testing.expect(eventPatternMatch("s3:ObjectCreated:*", "s3:ObjectCreated:Put"));
    try std.testing.expect(eventPatternMatch("s3:ObjectCreated:*", "s3:ObjectCreated:CompleteMultipartUpload"));
    try std.testing.expect(!eventPatternMatch("s3:ObjectCreated:*", "s3:ObjectRemoved:Delete"));
}

test "configAllows no events configured drops all" {
    const a = std.testing.allocator;
    try std.testing.expect(!configAllows(a, "", "s3:ObjectCreated:Put", "foo.txt"));
}

test "configAllows matches wildcard event" {
    const a = std.testing.allocator;
    const xml_text =
        \\<NotificationConfiguration><Event>s3:ObjectCreated:*</Event></NotificationConfiguration>
    ;
    try std.testing.expect(configAllows(a, xml_text, "s3:ObjectCreated:Put", "foo.txt"));
    try std.testing.expect(!configAllows(a, xml_text, "s3:ObjectRemoved:Delete", "foo.txt"));
}

test "configAllows prefix filter blocks non-matching key" {
    const a = std.testing.allocator;
    const xml_text =
        \\<NotificationConfiguration>
        \\  <Event>s3:ObjectCreated:*</Event>
        \\  <Filter><S3Key>
        \\    <FilterRule><Name>prefix</Name><Value>images/</Value></FilterRule>
        \\  </S3Key></Filter>
        \\</NotificationConfiguration>
    ;
    try std.testing.expect(configAllows(a, xml_text, "s3:ObjectCreated:Put", "images/cat.jpg"));
    try std.testing.expect(!configAllows(a, xml_text, "s3:ObjectCreated:Put", "docs/readme.txt"));
}

test "configAllows suffix filter" {
    const a = std.testing.allocator;
    const xml_text =
        \\<NotificationConfiguration>
        \\  <Event>s3:ObjectRemoved:*</Event>
        \\  <Filter><S3Key>
        \\    <FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule>
        \\  </S3Key></Filter>
        \\</NotificationConfiguration>
    ;
    try std.testing.expect(configAllows(a, xml_text, "s3:ObjectRemoved:Delete", "images/cat.jpg"));
    try std.testing.expect(!configAllows(a, xml_text, "s3:ObjectRemoved:Delete", "images/cat.png"));
}

test "buildPayload contains expected fields" {
    const a = std.testing.allocator;
    const task = Task{
        .bucket = @constCast("my-bucket"),
        .key = @constCast("path/to/key.txt"),
        .name = .created_put,
        .size = 42,
        .etag = @constCast("abc123"),
    };
    const payload = try buildPayload(a, "us-east-1", task, "2026-07-02T00:00:00.000Z");
    defer a.free(payload);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"eventName\":\"s3:ObjectCreated:Put\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"my-bucket\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"key\":\"path/to/key.txt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"size\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"eTag\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"awsRegion\":\"us-east-1\"") != null);
}

test "jsonEscapeAlloc escapes quotes and backslashes" {
    const a = std.testing.allocator;
    const out = try jsonEscapeAlloc(a, "a\"b\\c");
    defer a.free(out);
    try std.testing.expectEqualStrings("a\\\"b\\\\c", out);
}
