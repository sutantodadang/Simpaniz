//! Cross-cluster server-side replication (SSR).
//!
//! Best-effort, last-write-wins async replicator. Successful local PUTs
//! enqueue a small task; a background worker drains the queue and HTTP-PUTs
//! the object to each configured target endpoint.
//!
//! Targets format (env `SIMPANIZ_REPL_TARGETS`):
//!     "<src-bucket>=>http(s)://host:port[/dst-bucket][,...]"
//!
//! Optional auth: env `SIMPANIZ_REPL_AUTH` is sent verbatim as the
//! `Authorization` header value if set (e.g. `Bearer <token>`).
//!
//! HTTP and HTTPS targets are both supported via std.http.Client.
//!
//! Persistence: tasks are appended to `<data_dir>/.simpaniz-repl/queue.log`
//! (newline-delimited JSON) and the line offset is recorded so we can mark
//! entries as completed in-place. On startup, undelivered entries are
//! replayed back into memory. The journal is compacted on startup if
//! all tasks are delivered.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const ClusterRuntime = @import("runtime.zig").ClusterRuntime;
const ClusterConfig = @import("runtime.zig").ClusterConfig;

pub const Target = struct {
    src_bucket: []const u8, // owned
    scheme: []const u8, // "http" or "https" (static literal)
    host: []const u8, // owned
    port: u16,
    dst_bucket: []const u8, // owned (defaults to src_bucket)
};

pub const Task = struct {
    bucket: []u8, // owned
    key: []u8, // owned
    etag: [32]u8,
    size: u64,
    mtime_s: i64,
    retries: u8 = 0,
    /// Byte offset of this task's '\n' terminator in the journal, or 0 if
    /// not journaled (e.g. a re-enqueued retry whose original line is the
    /// same record). The first byte of a journal entry is either ' ' (live)
    /// or 'X' (tombstoned).
    journal_offset: u64 = std.math.maxInt(u64),
};

pub const ReplStats = struct {
    queued: std.atomic.Value(u64) = .{ .raw = 0 },
    replicated: std.atomic.Value(u64) = .{ .raw = 0 },
    failed: std.atomic.Value(u64) = .{ .raw = 0 },
    pending: std.atomic.Value(u64) = .{ .raw = 0 },
};

pub const Replicator = struct {
    allocator: Allocator,
    targets: []Target,
    auth_header: ?[]const u8, // owned
    queue: std.ArrayList(Task),
    queue_mu: Thread.Mutex = .{},
    queue_cv: Thread.Condition = .{},
    stop: std.atomic.Value(bool) = .{ .raw = false },
    worker: ?Thread = null,
    stats: ReplStats = .{},

    /// Optional disk journal. When present, every enqueue appends a JSON line
    /// with a leading ' ' byte; successful delivery rewrites that byte to 'X'.
    journal: ?std.fs.File = null,
    journal_mu: Thread.Mutex = .{},

    pub fn init(allocator: Allocator, targets_raw: []const u8, auth: ?[]const u8) !*Replicator {
        const r = try allocator.create(Replicator);
        errdefer allocator.destroy(r);
        r.* = .{
            .allocator = allocator,
            .targets = try parseTargets(allocator, targets_raw),
            .auth_header = if (auth) |a| try allocator.dupe(u8, a) else null,
            .queue = std.ArrayList(Task){},
        };
        return r;
    }

    /// Open / create the on-disk journal under `data_dir/.simpaniz-repl/queue.log`
    /// and replay any pending (non-tombstoned) entries into the in-memory queue.
    pub fn attachJournal(self: *Replicator, data_dir: std.fs.Dir) !void {
        data_dir.makePath(".simpaniz-repl") catch {};
        const file = data_dir.createFile(".simpaniz-repl/queue.log", .{
            .read = true,
            .truncate = false,
            .exclusive = false,
        }) catch |e| switch (e) {
            error.PathAlreadyExists => try data_dir.openFile(".simpaniz-repl/queue.log", .{ .mode = .read_write }),
            else => return e,
        };
        self.journal = file;

        // Replay.
        try self.replayJournal();
    }

    fn replayJournal(self: *Replicator) !void {
        const f = self.journal orelse return;
        const sz = try f.getEndPos();
        if (sz == 0) return;

        const data = try self.allocator.alloc(u8, @intCast(sz));
        defer self.allocator.free(data);
        try f.seekTo(0);
        _ = try f.readAll(data);

        var live_count: u64 = 0;
        var i: u64 = 0;
        var line_start: u64 = 0;
        while (i < data.len) : (i += 1) {
            if (data[i] != '\n') continue;
            const line = data[line_start..i];
            const newline_off = i;
            line_start = i + 1;
            if (line.len == 0) continue;
            if (line[0] != ' ') continue; // tombstoned ('X') — skip
            const json = line[1..];
            const task = parseJournalLine(self.allocator, json, newline_off) catch continue;
            self.queue.append(self.allocator, task) catch break;
            _ = self.stats.pending.fetchAdd(1, .monotonic);
            _ = self.stats.queued.fetchAdd(1, .monotonic);
            live_count += 1;
        }

        // Compact if everything was delivered.
        if (live_count == 0) {
            try f.seekTo(0);
            try f.setEndPos(0);
        }
        std.log.info("ssr: journal replayed, {d} pending tasks", .{live_count});
    }

    fn parseJournalLine(allocator: Allocator, json: []const u8, journal_offset: u64) !Task {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        var t: Task = .{
            .bucket = try allocator.dupe(u8, obj.get("b").?.string),
            .key = try allocator.dupe(u8, obj.get("k").?.string),
            .etag = undefined,
            .size = @intCast(obj.get("s").?.integer),
            .mtime_s = obj.get("m").?.integer,
            .journal_offset = journal_offset,
        };
        const etag_s = obj.get("e").?.string;
        if (etag_s.len != 32) {
            allocator.free(t.bucket);
            allocator.free(t.key);
            return error.BadJournalLine;
        }
        @memcpy(&t.etag, etag_s);
        return t;
    }

    fn appendJournal(self: *Replicator, task: *Task) void {
        const f = self.journal orelse return;
        var buf: [1024]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, " {{\"b\":\"{s}\",\"k\":\"{s}\",\"e\":\"{s}\",\"s\":{d},\"m\":{d}}}\n", .{
            task.bucket, task.key, task.etag, task.size, task.mtime_s,
        }) catch return;

        self.journal_mu.lock();
        defer self.journal_mu.unlock();
        const end = f.getEndPos() catch return;
        f.seekTo(end) catch return;
        f.writeAll(json) catch return;
        // Offset of the leading ' ' byte we'll later overwrite with 'X'.
        task.journal_offset = end;
    }

    fn tombstoneJournal(self: *Replicator, journal_offset: u64) void {
        const f = self.journal orelse return;
        if (journal_offset == std.math.maxInt(u64)) return;
        self.journal_mu.lock();
        defer self.journal_mu.unlock();
        f.seekTo(journal_offset) catch return;
        f.writeAll("X") catch return;
    }

    pub fn deinit(self: *Replicator) void {
        self.shutdown();
        for (self.targets) |t| {
            self.allocator.free(t.src_bucket);
            self.allocator.free(t.host);
            self.allocator.free(t.dst_bucket);
        }
        self.allocator.free(self.targets);
        if (self.auth_header) |a| self.allocator.free(a);
        for (self.queue.items) |task| {
            self.allocator.free(task.bucket);
            self.allocator.free(task.key);
        }
        self.queue.deinit(self.allocator);
        if (self.journal) |*f| f.close();
        self.allocator.destroy(self);
    }

    pub fn start(self: *Replicator) !void {
        if (self.targets.len == 0) return;
        if (self.worker != null) return;
        self.worker = try Thread.spawn(.{}, workerLoop, .{self});
    }

    pub fn shutdown(self: *Replicator) void {
        self.stop.store(true, .seq_cst);
        self.queue_mu.lock();
        self.queue_cv.broadcast();
        self.queue_mu.unlock();
        if (self.worker) |w| {
            w.join();
            self.worker = null;
        }
    }

    pub fn enqueue(
        self: *Replicator,
        bucket: []const u8,
        key: []const u8,
        etag_hex: [32]u8,
        size: u64,
        mtime_s: i64,
    ) !void {
        var matched = false;
        for (self.targets) |t| {
            if (std.mem.eql(u8, t.src_bucket, bucket)) {
                matched = true;
                break;
            }
        }
        if (!matched) return;

        const b = try self.allocator.dupe(u8, bucket);
        errdefer self.allocator.free(b);
        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);

        var task: Task = .{
            .bucket = b,
            .key = k,
            .etag = etag_hex,
            .size = size,
            .mtime_s = mtime_s,
        };
        self.appendJournal(&task);

        self.queue_mu.lock();
        defer self.queue_mu.unlock();
        try self.queue.append(self.allocator, task);
        _ = self.stats.queued.fetchAdd(1, .monotonic);
        _ = self.stats.pending.fetchAdd(1, .monotonic);
        self.queue_cv.signal();
    }

    fn workerLoop(self: *Replicator) void {
        while (!self.stop.load(.seq_cst)) {
            const maybe = self.popNext();
            if (maybe) |task| {
                self.process(task);
            } else {
                self.queue_mu.lock();
                if (self.queue.items.len == 0 and !self.stop.load(.seq_cst)) {
                    self.queue_cv.timedWait(&self.queue_mu, 500 * std.time.ns_per_ms) catch {};
                }
                self.queue_mu.unlock();
            }
        }
    }

    fn popNext(self: *Replicator) ?Task {
        self.queue_mu.lock();
        defer self.queue_mu.unlock();
        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }

    fn process(self: *Replicator, task_in: Task) void {
        var task = task_in;
        defer {
            self.allocator.free(task.bucket);
            self.allocator.free(task.key);
            _ = self.stats.pending.fetchSub(1, .monotonic);
        }

        const cr = current_runtime orelse {
            _ = self.stats.failed.fetchAdd(1, .monotonic);
            return;
        };

        const meta_opt = cr.readMeta(task.bucket, task.key, self.allocator) catch {
            _ = self.stats.failed.fetchAdd(1, .monotonic);
            return;
        };
        const meta = meta_opt orelse {
            _ = self.stats.failed.fetchAdd(1, .monotonic);
            return;
        };
        defer self.allocator.free(meta.content_type);

        const data = cr.orchestrator.get(task.bucket, task.key, meta.shard_size, meta.original_size, self.allocator) catch {
            _ = self.stats.failed.fetchAdd(1, .monotonic);
            return;
        };
        defer self.allocator.free(data);

        var any_ok = false;
        for (self.targets) |t| {
            if (!std.mem.eql(u8, t.src_bucket, task.bucket)) continue;
            self.deliver(t, task.key, data, task.mtime_s) catch {
                continue;
            };
            any_ok = true;
        }

        if (any_ok) {
            _ = self.stats.replicated.fetchAdd(1, .monotonic);
            self.tombstoneJournal(task.journal_offset);
        } else {
            _ = self.stats.failed.fetchAdd(1, .monotonic);
            task.retries +%= 1;
            if (task.retries < 5) {
                std.Thread.sleep(@as(u64, task.retries) * 500 * std.time.ns_per_ms);
                self.queue_mu.lock();
                defer self.queue_mu.unlock();
                const b = self.allocator.dupe(u8, task.bucket) catch return;
                const k = self.allocator.dupe(u8, task.key) catch {
                    self.allocator.free(b);
                    return;
                };
                self.queue.append(self.allocator, .{
                    .bucket = b,
                    .key = k,
                    .etag = task.etag,
                    .size = task.size,
                    .mtime_s = task.mtime_s,
                    .retries = task.retries,
                    .journal_offset = task.journal_offset,
                }) catch {
                    self.allocator.free(b);
                    self.allocator.free(k);
                    return;
                };
                _ = self.stats.pending.fetchAdd(1, .monotonic);
            } else {
                // Give up — tombstone so we don't replay it forever.
                self.tombstoneJournal(task.journal_offset);
            }
        }
    }

    /// Deliver one PUT to a single target via std.http.Client (handles HTTP and HTTPS).
    fn deliver(self: *Replicator, target: Target, key: []const u8, data: []const u8, mtime_s: i64) !void {
        const a = self.allocator;
        const url = try std.fmt.allocPrint(a, "{s}://{s}:{d}/{s}/{s}", .{
            target.scheme, target.host, target.port, target.dst_bucket, key,
        });
        defer a.free(url);

        var mtime_buf: [32]u8 = undefined;
        const mtime_s_str = try std.fmt.bufPrint(&mtime_buf, "{d}", .{mtime_s});

        var hdrs = std.ArrayList(std.http.Header){};
        defer hdrs.deinit(a);
        try hdrs.append(a, .{ .name = "x-amz-meta-mtime", .value = mtime_s_str });
        if (self.auth_header) |h| try hdrs.append(a, .{ .name = "Authorization", .value = h });

        var client = std.http.Client{ .allocator = a };
        defer client.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .PUT,
            .payload = data,
            .headers = .{ .content_type = .{ .override = "application/octet-stream" } },
            .extra_headers = hdrs.items,
            .keep_alive = false,
        }) catch return error.DeliverFailed;

        const code = @intFromEnum(result.status);
        if (code < 200 or code >= 300) return error.PeerRejected;
    }
};

/// Module-global pointer to the active ClusterRuntime; installed by the
/// runtime's startReplication.
pub var current_runtime: ?*ClusterRuntime = null;

fn parseTargets(allocator: Allocator, raw: []const u8) ![]Target {
    var list = std.ArrayList(Target){};
    errdefer {
        for (list.items) |t| {
            allocator.free(t.src_bucket);
            allocator.free(t.host);
            allocator.free(t.dst_bucket);
        }
        list.deinit(allocator);
    }
    if (raw.len == 0) return try list.toOwnedSlice(allocator);

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t");
        if (entry.len == 0) continue;
        const arrow = std.mem.indexOf(u8, entry, "=>") orelse continue;
        const src_bucket = std.mem.trim(u8, entry[0..arrow], " \t");
        const url = std.mem.trim(u8, entry[arrow + 2 ..], " \t");

        const scheme_sep = std.mem.indexOf(u8, url, "://") orelse continue;
        const scheme = url[0..scheme_sep];
        const after = url[scheme_sep + 3 ..];

        const path_sep = std.mem.indexOfScalar(u8, after, '/');
        const hostport = if (path_sep) |p| after[0..p] else after;
        const path = if (path_sep) |p| after[p + 1 ..] else &[_]u8{};

        var host: []const u8 = hostport;
        var port: u16 = if (std.mem.eql(u8, scheme, "https")) 443 else 80;
        if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |c| {
            host = hostport[0..c];
            port = std.fmt.parseInt(u16, hostport[c + 1 ..], 10) catch port;
        }

        const dst_bucket = if (path.len > 0) path else src_bucket;

        try list.append(allocator, .{
            .src_bucket = try allocator.dupe(u8, src_bucket),
            .scheme = if (std.mem.eql(u8, scheme, "https")) "https" else "http",
            .host = try allocator.dupe(u8, host),
            .port = port,
            .dst_bucket = try allocator.dupe(u8, dst_bucket),
        });
    }
    return try list.toOwnedSlice(allocator);
}

test "parseTargets — http + https" {
    const a = std.testing.allocator;
    const t = try parseTargets(a, "src=>http://peer:9000/dst, sec=>https://other:443");
    defer {
        for (t) |x| {
            a.free(x.src_bucket);
            a.free(x.host);
            a.free(x.dst_bucket);
        }
        a.free(t);
    }
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("http", t[0].scheme);
    try std.testing.expectEqualStrings("https", t[1].scheme);
    try std.testing.expectEqual(@as(u16, 443), t[1].port);
    try std.testing.expectEqualStrings("sec", t[1].dst_bucket); // defaults to src
}

test "journal append + tombstone roundtrip" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var r = try Replicator.init(a, "src=>http://peer:80", null);
    defer r.deinit();
    try r.attachJournal(tmp.dir);

    try r.enqueue("src", "key", "0123456789abcdef0123456789abcdef".*, 4, 1700000000);
    try std.testing.expectEqual(@as(usize, 1), r.queue.items.len);

    const t = r.queue.orderedRemove(0);
    defer {
        a.free(t.bucket);
        a.free(t.key);
    }
    r.tombstoneJournal(t.journal_offset);

    // Reopen and replay — should be empty.
    var r2 = try Replicator.init(a, "src=>http://peer:80", null);
    defer r2.deinit();
    try r2.attachJournal(tmp.dir);
    try std.testing.expectEqual(@as(usize, 0), r2.queue.items.len);
}
