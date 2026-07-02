//! Persistent sorted-segment metadata index (LSM-lite, zero deps) for fast
//! `ListObjectsV2` on huge buckets with flat memory, replacing the
//! FS-walk-and-sort hot path in `storage/objects.zig:listObjects` (which
//! remains as the bootstrap source and the fallback path).
//!
//! Per-bucket on-disk layout under `<bucket>/.simpaniz-index/` (the name
//! starts with `paths.reserved_prefix` so every existing walker already
//! skips it):
//!   wal.log          — append-only mutation log, fsync'd per append.
//!   seg-NNNNNNNN.idx — a single immutable sorted segment.
//!
//! Deliberate simplification vs. a "real" LSM: compaction always merges the
//! overlay with the *entire* existing segment into one brand-new segment, so
//! there is never more than one segment file on disk at a time. That means
//! `list()` only ever needs a 2-way merge (overlay + the one segment) instead
//! of a general k-way merge across many segment files, while still matching
//! the spec's on-disk segment format byte-for-byte.
//!
//! Single-node only: cluster mode keeps using the FS-walk fallback in
//! `storage/objects.zig` (see the `ctx.cluster == null` guards at each call
//! site in handlers.zig/server.zig).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const File = std.fs.File;
const Io = std.Io;

const util = @import("util.zig");
const xml = @import("xml.zig");
const paths = @import("storage/paths.zig");
const types = @import("storage/types.zig");
const internal = @import("storage/internal.zig");

const ListOpts = types.ListOpts;
const ListPage = types.ListPage;

/// Directory name for the per-bucket index store. Starts with
/// `paths.reserved_prefix` so every existing FS walker (listObjects,
/// lifecycle sweep, bitrot scrub) already skips it.
pub const index_dir_name = ".simpaniz-index";
const wal_name = "wal.log";
const seg_magic: u32 = 0x53504958; // "SPIX" little-endian
const footer_stride: u64 = 64;
const compact_threshold_default: usize = 8192;
const read_buf_size: usize = 8192;

// ── Record format (shared byte layout for WAL entries and segment records) ──
// op:u8 ('+'/'-') | key_len:u16 | key bytes | size:u64 | mtime_ns:i128 |
// etag_len:u8 | etag bytes  (little-endian integers throughout)

pub const Op = enum(u8) { upsert = '+', tombstone = '-' };

pub const Record = struct {
    op: Op,
    key: []const u8,
    size: u64,
    mtime_ns: i128,
    etag: []const u8,
};

fn recordEncodedLen(key_len: usize, etag_len: usize) usize {
    return 1 + 2 + key_len + 8 + 16 + 1 + etag_len;
}

/// Encode a record for the WAL. Caller owns the returned buffer.
pub fn encodeRecord(allocator: Allocator, rec: Record) ![]u8 {
    if (rec.key.len > std.math.maxInt(u16)) return error.InvalidKey;
    if (rec.etag.len > std.math.maxInt(u8)) return error.InvalidKey;
    const buf = try allocator.alloc(u8, recordEncodedLen(rec.key.len, rec.etag.len));
    var i: usize = 0;
    buf[i] = @intFromEnum(rec.op);
    i += 1;
    std.mem.writeInt(u16, buf[i..][0..2], @intCast(rec.key.len), .little);
    i += 2;
    @memcpy(buf[i .. i + rec.key.len], rec.key);
    i += rec.key.len;
    std.mem.writeInt(u64, buf[i..][0..8], rec.size, .little);
    i += 8;
    std.mem.writeInt(i128, buf[i..][0..16], rec.mtime_ns, .little);
    i += 16;
    buf[i] = @intCast(rec.etag.len);
    i += 1;
    @memcpy(buf[i .. i + rec.etag.len], rec.etag);
    i += rec.etag.len;
    return buf;
}

pub const DecodedRecord = struct {
    op: Op,
    key: []const u8,
    size: u64,
    mtime_ns: i128,
    etag: []const u8,
    /// Bytes consumed from the input slice.
    consumed: usize,
};

/// Decode a record from `bytes` (WAL replay). Returned `key`/`etag` are
/// slices into `bytes` — caller dupes if it needs to outlive the buffer.
pub fn decodeRecord(bytes: []const u8) !DecodedRecord {
    if (bytes.len < 3) return error.Corrupt;
    const op: Op = switch (bytes[0]) {
        '+' => .upsert,
        '-' => .tombstone,
        else => return error.Corrupt,
    };
    var i: usize = 1;
    const key_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (bytes.len < i + key_len) return error.Corrupt;
    const key = bytes[i .. i + key_len];
    i += key_len;
    if (bytes.len < i + 8 + 16 + 1) return error.Corrupt;
    const size = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const mtime_ns = std.mem.readInt(i128, bytes[i..][0..16], .little);
    i += 16;
    const etag_len = bytes[i];
    i += 1;
    if (bytes.len < i + etag_len) return error.Corrupt;
    const etag = bytes[i .. i + etag_len];
    i += etag_len;
    return .{ .op = op, .key = key, .size = size, .mtime_ns = mtime_ns, .etag = etag, .consumed = i };
}

// ── Low-level buffered reader over a file region, driven by pread so it
//    never needs a stateful OS cursor and can seek cheaply. Used for both
//    scanning segment records and parsing the sparse footer, bounded to
//    `read_buf_size` bytes resident at a time regardless of file size. ──

const ByteCursor = struct {
    file: File,
    pos: u64,
    end: u64,
    buf: [read_buf_size]u8 = undefined,
    buf_len: usize = 0,
    buf_off: usize = 0,

    fn fill(self: *ByteCursor) !void {
        if (self.buf_off < self.buf_len) return;
        if (self.pos >= self.end) {
            self.buf_len = 0;
            self.buf_off = 0;
            return;
        }
        const want = @min(self.buf.len, @as(usize, @intCast(self.end - self.pos)));
        const n = try self.file.pread(self.buf[0..want], self.pos);
        if (n == 0) return error.Corrupt;
        self.buf_len = n;
        self.buf_off = 0;
    }

    fn readByte(self: *ByteCursor) !u8 {
        try self.fill();
        if (self.buf_off >= self.buf_len) return error.Corrupt;
        const b = self.buf[self.buf_off];
        self.buf_off += 1;
        self.pos += 1;
        return b;
    }

    fn readBytesInto(self: *ByteCursor, out: []u8) !void {
        var got: usize = 0;
        while (got < out.len) {
            try self.fill();
            if (self.buf_off >= self.buf_len) return error.Corrupt;
            const avail = self.buf_len - self.buf_off;
            const take = @min(avail, out.len - got);
            @memcpy(out[got .. got + take], self.buf[self.buf_off .. self.buf_off + take]);
            self.buf_off += take;
            self.pos += take;
            got += take;
        }
    }

    fn readBytesAlloc(self: *ByteCursor, gpa: Allocator, n: usize) ![]u8 {
        const out = try gpa.alloc(u8, n);
        errdefer gpa.free(out);
        try self.readBytesInto(out);
        return out;
    }

    fn readU16(self: *ByteCursor) !u16 {
        var b: [2]u8 = undefined;
        try self.readBytesInto(&b);
        return std.mem.readInt(u16, &b, .little);
    }
    fn readU64(self: *ByteCursor) !u64 {
        var b: [8]u8 = undefined;
        try self.readBytesInto(&b);
        return std.mem.readInt(u64, &b, .little);
    }
    fn readI128(self: *ByteCursor) !i128 {
        var b: [16]u8 = undefined;
        try self.readBytesInto(&b);
        return std.mem.readInt(i128, &b, .little);
    }

    fn atEnd(self: *const ByteCursor) bool {
        return self.pos >= self.end and self.buf_off >= self.buf_len;
    }

    /// Read the next record in [pos, end). Returns null past the end.
    /// error.Corrupt signals malformed data — callers treat this as "the
    /// index is corrupt, rebuild from scratch."
    fn nextRecord(self: *ByteCursor, gpa: Allocator) !?Record {
        if (self.atEnd()) return null;
        const op_byte = try self.readByte();
        const op: Op = switch (op_byte) {
            '+' => .upsert,
            '-' => .tombstone,
            else => return error.Corrupt,
        };
        const key_len = try self.readU16();
        if (key_len == 0 or key_len > util.max_key_length) return error.Corrupt;
        const key = try self.readBytesAlloc(gpa, key_len);
        errdefer gpa.free(key);
        const size = try self.readU64();
        const mtime_ns = try self.readI128();
        const etag_len = try self.readByte();
        const etag = try self.readBytesAlloc(gpa, etag_len);
        return Record{ .op = op, .key = key, .size = size, .mtime_ns = mtime_ns, .etag = etag };
    }
};

fn freeRecord(gpa: Allocator, r: Record) void {
    gpa.free(r.key);
    gpa.free(r.etag);
}

// ── Segment: immutable sorted file with a sparse in-memory footer index. ──

const FooterEntry = struct { offset: u64, key: []u8 };

const Segment = struct {
    name: []u8, // owned; e.g. "seg-00000001.idx"
    file: File,
    record_count: u64,
    data_start: u64, // = 12 (4-byte magic + 8-byte count)
    data_end: u64, // = footer_offset
    footer: []FooterEntry, // owned, ~1/64th of record_count entries

    fn close(self: *Segment, gpa: Allocator) void {
        self.file.close();
        for (self.footer) |f| gpa.free(f.key);
        gpa.free(self.footer);
        gpa.free(self.name);
    }

    fn newCursor(self: *const Segment) ByteCursor {
        return .{ .file = self.file, .pos = self.data_start, .end = self.data_end };
    }

    /// Offset of the greatest footer entry whose key is <= target, or
    /// `data_start` if target sorts before every footer entry.
    fn seekOffsetFor(self: *const Segment, target: []const u8) u64 {
        if (self.footer.len == 0) return self.data_start;
        var lo: usize = 0;
        var hi: usize = self.footer.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.order(u8, self.footer[mid].key, target) != .gt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo == 0) return self.data_start;
        return self.footer[lo - 1].offset;
    }
};

fn openSegment(idx_dir: Dir, gpa: Allocator, name: []const u8) !Segment {
    var file = try idx_dir.openFile(name, .{});
    errdefer file.close();
    const stat = try file.stat();
    if (stat.size < 12 + 16) return error.Corrupt;

    var head: [12]u8 = undefined;
    if (try file.pread(&head, 0) != 12) return error.Corrupt;
    if (std.mem.readInt(u32, head[0..4], .little) != seg_magic) return error.Corrupt;
    const record_count = std.mem.readInt(u64, head[4..12], .little);

    var tail: [16]u8 = undefined;
    if (try file.pread(&tail, stat.size - 16) != 16) return error.Corrupt;
    const footer_entry_count = std.mem.readInt(u32, tail[0..4], .little);
    const footer_offset = std.mem.readInt(u64, tail[4..12], .little);
    if (std.mem.readInt(u32, tail[12..16], .little) != seg_magic) return error.Corrupt;
    if (footer_offset < 12 or footer_offset > stat.size - 16) return error.Corrupt;

    const footer = try gpa.alloc(FooterEntry, footer_entry_count);
    var filled: usize = 0;
    errdefer {
        for (footer[0..filled]) |f| gpa.free(f.key);
        gpa.free(footer);
    }

    var cur = ByteCursor{ .file = file, .pos = footer_offset, .end = stat.size - 16 };
    var i: usize = 0;
    while (i < footer_entry_count) : (i += 1) {
        const off = try cur.readU64();
        const klen = try cur.readU16();
        if (klen == 0 or klen > util.max_key_length) return error.Corrupt;
        const key = try cur.readBytesAlloc(gpa, klen);
        footer[i] = .{ .offset = off, .key = key };
        filled += 1;
    }

    return .{
        .name = try gpa.dupe(u8, name),
        .file = file,
        .record_count = record_count,
        .data_start = 12,
        .data_end = footer_offset,
        .footer = footer,
    };
}

// ── Segment writer: shared by bootstrap and compaction. ──

fn writeSegHeader(w: *Io.Writer) !void {
    var buf: [12]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], seg_magic, .little);
    std.mem.writeInt(u64, buf[4..12], 0, .little); // record_count placeholder, patched later
    try w.writeAll(&buf);
}

fn writeRecordAndTrack(
    w: *Io.Writer,
    gpa: Allocator,
    footer: *std.ArrayList(FooterEntry),
    count: *u64,
    offset: *u64,
    key: []const u8,
    size: u64,
    mtime_ns: i128,
    etag: []const u8,
) !void {
    var hdr: [3]u8 = undefined;
    hdr[0] = '+';
    std.mem.writeInt(u16, hdr[1..3], @intCast(key.len), .little);
    try w.writeAll(&hdr);
    try w.writeAll(key);
    var mid: [24]u8 = undefined;
    std.mem.writeInt(u64, mid[0..8], size, .little);
    std.mem.writeInt(i128, mid[8..24], mtime_ns, .little);
    try w.writeAll(&mid);
    try w.writeAll(&[_]u8{@intCast(etag.len)});
    try w.writeAll(etag);

    if (count.* % footer_stride == 0) {
        try footer.append(gpa, .{ .offset = offset.*, .key = try gpa.dupe(u8, key) });
    }
    offset.* += recordEncodedLen(key.len, etag.len);
    count.* += 1;
}

fn writeSegTrailer(w: *Io.Writer, footer: *const std.ArrayList(FooterEntry), footer_offset: u64) !void {
    for (footer.items) |f| {
        var hdr: [10]u8 = undefined;
        std.mem.writeInt(u64, hdr[0..8], f.offset, .little);
        std.mem.writeInt(u16, hdr[8..10], @intCast(f.key.len), .little);
        try w.writeAll(&hdr);
        try w.writeAll(f.key);
    }
    var tail: [16]u8 = undefined;
    std.mem.writeInt(u32, tail[0..4], @intCast(footer.items.len), .little);
    std.mem.writeInt(u64, tail[4..12], footer_offset, .little);
    std.mem.writeInt(u32, tail[12..16], seg_magic, .little);
    try w.writeAll(&tail);
}

fn patchRecordCountAndFinish(file: *File, count: u64) !void {
    var count_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &count_buf, count, .little);
    try file.pwriteAll(&count_buf, 4);
    file.sync() catch {};
}

// ── In-memory overlay entry (mutation log replayed / not-yet-compacted). ──

const Entry = struct {
    key: []u8, // owned
    tomb: bool,
    size: u64,
    mtime_ns: i128,
    etag: []u8, // owned; empty for tombstones
};

const OverlayFind = union(enum) { found: usize, insert_at: usize };

fn overlayFind(items: []const Entry, key: []const u8) OverlayFind {
    var lo: usize = 0;
    var hi: usize = items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, items[mid].key, key)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return .{ .found = mid },
        }
    }
    return .{ .insert_at = lo };
}

fn overlayPutRaw(gpa: Allocator, overlay: *std.ArrayList(Entry), key: []const u8, tomb: bool, size: u64, mtime_ns: i128, etag: []const u8) !void {
    switch (overlayFind(overlay.items, key)) {
        .found => |i| {
            const etag_owned = try gpa.dupe(u8, etag);
            gpa.free(overlay.items[i].etag);
            overlay.items[i].tomb = tomb;
            overlay.items[i].size = size;
            overlay.items[i].mtime_ns = mtime_ns;
            overlay.items[i].etag = etag_owned;
        },
        .insert_at => |i| {
            const key_owned = try gpa.dupe(u8, key);
            errdefer gpa.free(key_owned);
            const etag_owned = try gpa.dupe(u8, etag);
            errdefer gpa.free(etag_owned);
            try overlay.insert(gpa, i, .{ .key = key_owned, .tomb = tomb, .size = size, .mtime_ns = mtime_ns, .etag = etag_owned });
        },
    }
}

/// First index `i` such that `items[i].key` is >= bound (inclusive) or >
/// bound (exclusive).
fn overlayStartIndex(items: []const Entry, bound: []const u8, inclusive: bool) usize {
    var lo: usize = 0;
    var hi: usize = items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const cmp = std.mem.order(u8, items[mid].key, bound);
        const before = if (inclusive) cmp == .lt else (cmp == .lt or cmp == .eq);
        if (before) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/// Seek a segment cursor near `bound` via the sparse footer, then scan
/// forward to the exact first record satisfying the bound. Returns the
/// positioned cursor plus the first matching record (if any), which the
/// caller owns (gpa-allocated).
fn segmentSeekPeek(seg: *const Segment, gpa: Allocator, bound: []const u8, inclusive: bool) !struct { cursor: ByteCursor, peek: ?Record } {
    var cur = seg.newCursor();
    cur.pos = seg.seekOffsetFor(bound);
    while (true) {
        const r = (try cur.nextRecord(gpa)) orelse return .{ .cursor = cur, .peek = null };
        const cmp = std.mem.order(u8, r.key, bound);
        const keep = if (inclusive) cmp != .lt else cmp == .gt;
        if (keep) return .{ .cursor = cur, .peek = r };
        freeRecord(gpa, r);
    }
}

/// Bootstrap-time / test-time object metadata lookup: mirrors
/// `storage/objects.zig:listObjects` (lines ~428-448) exactly, including its
/// quirk of reporting the live filesystem stat (size/mtime) rather than the
/// metadata sidecar's recorded values, so a full rebuild is byte-for-byte
/// equivalent to the old FS-walk listing.
fn readObjectMetaForIndex(bucket_dir: Dir, gpa: Allocator, key: []const u8) !struct { size: u64, mtime_ns: i128, etag: []const u8 } {
    const stat = try bucket_dir.statFile(key);
    const meta = internal.readMetadata(bucket_dir, gpa, key) catch {
        return .{ .size = stat.size, .mtime_ns = stat.mtime, .etag = try gpa.dupe(u8, "unknown") };
    };
    defer gpa.free(meta.content_type);
    if (meta.encryption) |enc| {
        gpa.free(enc.alg);
        gpa.free(enc.wrapped_dek_b64);
        gpa.free(enc.wrap_nonce_b64);
        gpa.free(enc.sse_c_key_md5);
        gpa.free(enc.kms_key_id);
    }
    return .{ .size = stat.size, .mtime_ns = stat.mtime, .etag = meta.etag };
}

// ── BucketIndex: per-bucket LSM-lite state. ──

const BucketIndex = struct {
    gpa: Allocator,
    bucket_dir: Dir,
    idx_dir: Dir,
    wal_file: File,
    wal_write_pos: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    overlay: std.ArrayList(Entry) = .{},
    segment: ?Segment = null,
    seg_counter: u32 = 0,
    compact_threshold: usize,

    fn deinit(self: *BucketIndex) void {
        for (self.overlay.items) |e| {
            self.gpa.free(e.key);
            self.gpa.free(e.etag);
        }
        self.overlay.deinit(self.gpa);
        if (self.segment) |*s| s.close(self.gpa);
        self.wal_file.close();
        self.idx_dir.close();
        self.bucket_dir.close();
    }

    /// Close handles and remove the on-disk index directory. Used when the
    /// bucket itself is being deleted.
    fn closeHandlesAndDeleteOnDisk(self: *BucketIndex) void {
        for (self.overlay.items) |e| {
            self.gpa.free(e.key);
            self.gpa.free(e.etag);
        }
        self.overlay.deinit(self.gpa);
        if (self.segment) |*s| s.close(self.gpa);
        self.wal_file.close();
        self.idx_dir.close();
        self.bucket_dir.deleteTree(index_dir_name) catch |e| {
            std.log.warn("index: deleteTree failed: {}", .{e});
        };
        self.bucket_dir.close();
    }

    fn appendWal(self: *BucketIndex, rec: Record) !void {
        const bytes = try encodeRecord(self.gpa, rec);
        defer self.gpa.free(bytes);
        try self.wal_file.pwriteAll(bytes, self.wal_write_pos);
        self.wal_write_pos += bytes.len;
        self.wal_file.sync() catch {};
    }

    pub fn upsert(self: *BucketIndex, key: []const u8, size: u64, mtime_ns: i128, etag: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.appendWal(.{ .op = .upsert, .key = key, .size = size, .mtime_ns = mtime_ns, .etag = etag });
        try overlayPutRaw(self.gpa, &self.overlay, key, false, size, mtime_ns, etag);
        if (self.overlay.items.len >= self.compact_threshold) try self.compact();
    }

    pub fn remove(self: *BucketIndex, key: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.appendWal(.{ .op = .tombstone, .key = key, .size = 0, .mtime_ns = 0, .etag = "" });
        try overlayPutRaw(self.gpa, &self.overlay, key, true, 0, 0, "");
        if (self.overlay.items.len >= self.compact_threshold) try self.compact();
    }

    /// Merge overlay + existing segment into one new segment, dropping
    /// tombstones (safe since the merge always covers the *entire* live
    /// data set — see module doc). Must be called with `mutex` held.
    fn compact(self: *BucketIndex) !void {
        const new_num = self.seg_counter + 1;
        var tmp_buf: [40]u8 = undefined;
        var final_buf: [40]u8 = undefined;
        const tmp_name = try std.fmt.bufPrint(&tmp_buf, "seg-{d:0>8}.idx.tmp", .{new_num});
        const final_name = try std.fmt.bufPrint(&final_buf, "seg-{d:0>8}.idx", .{new_num});

        var seg_file = try self.idx_dir.createFile(tmp_name, .{ .truncate = true });
        errdefer self.idx_dir.deleteFile(tmp_name) catch {};
        var write_buf: [64 * 1024]u8 = undefined;
        var fw = seg_file.writer(&write_buf);
        const w = &fw.interface;
        try writeSegHeader(w);

        var footer = std.ArrayList(FooterEntry){};
        defer {
            for (footer.items) |f| self.gpa.free(f.key);
            footer.deinit(self.gpa);
        }

        var count: u64 = 0;
        var offset: u64 = 12;

        var old_cursor: ?ByteCursor = if (self.segment) |*s| s.newCursor() else null;
        var old_peek: ?Record = if (old_cursor) |*c| try c.nextRecord(self.gpa) else null;
        defer if (old_peek) |r| freeRecord(self.gpa, r);

        var oi: usize = 0;
        while (true) {
            const has_ov = oi < self.overlay.items.len;
            const has_old = old_peek != null;
            if (!has_ov and !has_old) break;

            if (has_ov and has_old) {
                const ov = self.overlay.items[oi];
                const old = old_peek.?;
                const cmp = std.mem.order(u8, ov.key, old.key);
                if (cmp == .eq) {
                    freeRecord(self.gpa, old);
                    old_peek = if (old_cursor) |*c| try c.nextRecord(self.gpa) else null;
                    if (!ov.tomb) try writeRecordAndTrack(w, self.gpa, &footer, &count, &offset, ov.key, ov.size, ov.mtime_ns, ov.etag);
                    oi += 1;
                } else if (cmp == .lt) {
                    if (!ov.tomb) try writeRecordAndTrack(w, self.gpa, &footer, &count, &offset, ov.key, ov.size, ov.mtime_ns, ov.etag);
                    oi += 1;
                } else {
                    try writeRecordAndTrack(w, self.gpa, &footer, &count, &offset, old.key, old.size, old.mtime_ns, old.etag);
                    freeRecord(self.gpa, old);
                    old_peek = if (old_cursor) |*c| try c.nextRecord(self.gpa) else null;
                }
            } else if (has_ov) {
                const ov = self.overlay.items[oi];
                if (!ov.tomb) try writeRecordAndTrack(w, self.gpa, &footer, &count, &offset, ov.key, ov.size, ov.mtime_ns, ov.etag);
                oi += 1;
            } else {
                const old = old_peek.?;
                try writeRecordAndTrack(w, self.gpa, &footer, &count, &offset, old.key, old.size, old.mtime_ns, old.etag);
                freeRecord(self.gpa, old);
                old_peek = if (old_cursor) |*c| try c.nextRecord(self.gpa) else null;
            }
        }

        try writeSegTrailer(w, &footer, offset);
        try w.flush();
        try patchRecordCountAndFinish(&seg_file, count);
        seg_file.close();

        try self.idx_dir.rename(tmp_name, final_name);
        const new_segment = try openSegment(self.idx_dir, self.gpa, final_name);

        if (self.segment) |*old_seg| {
            self.idx_dir.deleteFile(old_seg.name) catch {};
            old_seg.close(self.gpa);
        }
        self.segment = new_segment;
        self.seg_counter = new_num;

        for (self.overlay.items) |e| {
            self.gpa.free(e.key);
            self.gpa.free(e.etag);
        }
        self.overlay.clearRetainingCapacity();

        self.wal_file.close();
        self.wal_file = try self.idx_dir.createFile(wal_name, .{ .truncate = true });
        self.wal_write_pos = 0;
    }

    pub fn list(self: *BucketIndex, allocator: Allocator, opts: ListOpts) !ListPage {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Resume semantics (must mirror storage/objects.zig:listObjects):
        // `continuation_token` is INCLUSIVE — it is the first key that was
        // NOT emitted on the previous page, so resume AT it (a strict-greater
        // seek here would silently drop one key per truncated page).
        // `start_after` stays EXCLUSIVE per S3. Prefix-only seeks are
        // inclusive at the prefix itself.
        var bound: []const u8 = opts.prefix;
        var bound_inclusive = true;
        if (opts.continuation_token.len > 0) {
            bound = opts.continuation_token;
        } else if (opts.start_after.len > 0) {
            bound = opts.start_after;
            bound_inclusive = false;
        }

        var oi: usize = if (bound.len > 0) overlayStartIndex(self.overlay.items, bound, bound_inclusive) else 0;

        var seg_cursor: ?ByteCursor = null;
        var seg_peek: ?Record = null;
        if (self.segment) |*seg| {
            if (bound.len > 0) {
                const sp = try segmentSeekPeek(seg, allocator, bound, bound_inclusive);
                seg_cursor = sp.cursor;
                seg_peek = sp.peek;
            } else {
                seg_cursor = seg.newCursor();
                seg_peek = try seg_cursor.?.nextRecord(allocator);
            }
        }
        defer if (seg_peek) |r| freeRecord(allocator, r);

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

        while (true) {
            var cand_key: []const u8 = undefined;
            var cand_size: u64 = 0;
            var cand_mtime: i128 = 0;
            var cand_etag: []const u8 = undefined;
            var cand_owned = false;
            var have_cand = false;

            while (true) {
                const has_ov = oi < self.overlay.items.len;
                const has_sg = seg_peek != null;
                if (!has_ov and !has_sg) break;

                if (has_ov and has_sg) {
                    const ov = self.overlay.items[oi];
                    const sg = seg_peek.?;
                    const cmp = std.mem.order(u8, ov.key, sg.key);
                    if (cmp == .eq) {
                        freeRecord(allocator, sg);
                        seg_peek = try seg_cursor.?.nextRecord(allocator);
                        if (ov.tomb) {
                            oi += 1;
                            continue;
                        }
                        cand_key = ov.key;
                        cand_size = ov.size;
                        cand_mtime = ov.mtime_ns;
                        cand_etag = ov.etag;
                        cand_owned = false;
                        oi += 1;
                        have_cand = true;
                        break;
                    } else if (cmp == .lt) {
                        if (ov.tomb) {
                            oi += 1;
                            continue;
                        }
                        cand_key = ov.key;
                        cand_size = ov.size;
                        cand_mtime = ov.mtime_ns;
                        cand_etag = ov.etag;
                        cand_owned = false;
                        oi += 1;
                        have_cand = true;
                        break;
                    } else {
                        cand_key = sg.key;
                        cand_size = sg.size;
                        cand_mtime = sg.mtime_ns;
                        cand_etag = sg.etag;
                        cand_owned = true;
                        seg_peek = try seg_cursor.?.nextRecord(allocator);
                        have_cand = true;
                        break;
                    }
                } else if (has_ov) {
                    const ov = self.overlay.items[oi];
                    if (ov.tomb) {
                        oi += 1;
                        continue;
                    }
                    cand_key = ov.key;
                    cand_size = ov.size;
                    cand_mtime = ov.mtime_ns;
                    cand_etag = ov.etag;
                    cand_owned = false;
                    oi += 1;
                    have_cand = true;
                    break;
                } else {
                    const sg = seg_peek.?;
                    cand_key = sg.key;
                    cand_size = sg.size;
                    cand_mtime = sg.mtime_ns;
                    cand_etag = sg.etag;
                    cand_owned = true;
                    seg_peek = try seg_cursor.?.nextRecord(allocator);
                    have_cand = true;
                    break;
                }
            }

            if (!have_cand) break;

            if (opts.prefix.len > 0 and !std.mem.startsWith(u8, cand_key, opts.prefix)) {
                if (cand_owned) {
                    allocator.free(cand_key);
                    allocator.free(cand_etag);
                }
                continue;
            }

            if (opts.delimiter.len == 1 and opts.delimiter[0] == '/') {
                const suffix_start = opts.prefix.len;
                if (std.mem.indexOfScalarPos(u8, cand_key, suffix_start, '/')) |slash| {
                    const cp = cand_key[0 .. slash + 1];
                    if (!prefixes_set.contains(cp)) {
                        if (emitted >= max) {
                            truncated = true;
                            next_token = try allocator.dupe(u8, cand_key);
                            if (cand_owned) {
                                allocator.free(cand_key);
                                allocator.free(cand_etag);
                            }
                            break;
                        }
                        const cp_owned = try allocator.dupe(u8, cp);
                        try prefixes_set.put(cp_owned, {});
                        emitted += 1;
                    }
                    if (cand_owned) {
                        allocator.free(cand_key);
                        allocator.free(cand_etag);
                    }
                    continue;
                }
            }

            if (emitted >= max) {
                truncated = true;
                next_token = try allocator.dupe(u8, cand_key);
                if (cand_owned) {
                    allocator.free(cand_key);
                    allocator.free(cand_etag);
                }
                break;
            }

            var lm_buf: [32]u8 = undefined;
            const lm = util.formatIso8601(&lm_buf, cand_mtime);
            const lm_owned = try allocator.dupe(u8, lm);
            const etag_quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{cand_etag});
            const key_owned = if (cand_owned) cand_key else try allocator.dupe(u8, cand_key);
            if (cand_owned) allocator.free(cand_etag);

            try objects.append(allocator, .{ .key = key_owned, .last_modified = lm_owned, .etag = etag_quoted, .size = cand_size });
            emitted += 1;
        }

        const cps = prefixes_set.keys();
        const cps_owned = try allocator.alloc([]const u8, cps.len);
        for (cps, 0..) |k, i| cps_owned[i] = k;

        return .{
            .objects = try objects.toOwnedSlice(allocator),
            .common_prefixes = cps_owned,
            .is_truncated = truncated,
            .next_continuation_token = next_token,
        };
    }
};

/// Full FS walk + sort, mirroring `storage/objects.zig:listObjects`'s
/// collection phase, then a single streamed write into segment #1. Used
/// both for first-ever indexing and for self-healing after corruption.
fn bootstrapBuild(gpa: Allocator, bucket_dir: Dir, threshold: usize) !BucketIndex {
    bucket_dir.makeDir(index_dir_name) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    var idx_dir = try bucket_dir.openDir(index_dir_name, .{ .iterate = true });
    errdefer idx_dir.close();

    var all = std.ArrayList([]u8){};
    defer {
        for (all.items) |k| gpa.free(k);
        all.deinit(gpa);
    }

    {
        var walker = try bucket_dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.startsWith(u8, entry.path, paths.reserved_prefix)) continue;
            const normalized = try gpa.dupe(u8, entry.path);
            for (normalized) |*c| if (c.* == '\\') {
                c.* = '/';
            };
            try all.append(gpa, normalized);
        }
    }
    std.mem.sort([]u8, all.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    const seg_final = "seg-00000001.idx";
    const seg_tmp = "seg-00000001.idx.tmp";

    var seg_file = try idx_dir.createFile(seg_tmp, .{ .truncate = true });
    errdefer idx_dir.deleteFile(seg_tmp) catch {};
    var write_buf: [64 * 1024]u8 = undefined;
    var fw = seg_file.writer(&write_buf);
    const w = &fw.interface;
    try writeSegHeader(w);

    var footer = std.ArrayList(FooterEntry){};
    defer {
        for (footer.items) |f| gpa.free(f.key);
        footer.deinit(gpa);
    }
    var count: u64 = 0;
    var offset: u64 = 12;

    for (all.items) |key| {
        const m = readObjectMetaForIndex(bucket_dir, gpa, key) catch continue;
        defer gpa.free(m.etag);
        try writeRecordAndTrack(w, gpa, &footer, &count, &offset, key, m.size, m.mtime_ns, m.etag);
    }

    try writeSegTrailer(w, &footer, offset);
    try w.flush();
    try patchRecordCountAndFinish(&seg_file, count);
    seg_file.close();

    try idx_dir.rename(seg_tmp, seg_final);
    const segment = try openSegment(idx_dir, gpa, seg_final);

    var wal_file = try idx_dir.createFile(wal_name, .{ .truncate = true });
    errdefer wal_file.close();

    std.log.info("index: bootstrapped bucket keys={d}", .{count});

    return .{
        .gpa = gpa,
        .bucket_dir = bucket_dir,
        .idx_dir = idx_dir,
        .wal_file = wal_file,
        .wal_write_pos = 0,
        .overlay = .{},
        .segment = segment,
        .seg_counter = 1,
        .compact_threshold = threshold,
    };
}

/// Open an already-built index directory, replaying its WAL. Returns
/// error.Corrupt (or any FS error) if the on-disk state is missing/invalid;
/// the caller then falls back to `bootstrapBuild`.
fn tryOpenExisting(gpa: Allocator, bucket_dir: Dir, threshold: usize) !BucketIndex {
    var idx_dir = try bucket_dir.openDir(index_dir_name, .{ .iterate = true });
    errdefer idx_dir.close();

    var seg_name: ?[]u8 = null;
    var seg_num_found: u32 = 0;
    {
        var it = idx_dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.startsWith(u8, entry.name, "seg-")) continue;
            if (!std.mem.endsWith(u8, entry.name, ".idx")) continue; // excludes ".idx.tmp"
            const num_str = entry.name["seg-".len .. entry.name.len - ".idx".len];
            const num = std.fmt.parseInt(u32, num_str, 10) catch continue;
            if (seg_name == null or num > seg_num_found) {
                if (seg_name) |old| gpa.free(old);
                seg_name = try gpa.dupe(u8, entry.name);
                seg_num_found = num;
            }
        }
    }
    defer if (seg_name) |n| gpa.free(n);

    var segment: ?Segment = null;
    errdefer if (segment) |*s| s.close(gpa);
    if (seg_name) |n| segment = try openSegment(idx_dir, gpa, n);

    var wal_file = try idx_dir.openFile(wal_name, .{});
    var wal_size: u64 = 0;
    var overlay = std.ArrayList(Entry){};
    errdefer {
        for (overlay.items) |e| {
            gpa.free(e.key);
            gpa.free(e.etag);
        }
        overlay.deinit(gpa);
    }
    {
        const stat = try wal_file.stat();
        wal_size = stat.size;
        if (stat.size > 0) {
            const bytes = try gpa.alloc(u8, @intCast(stat.size));
            defer gpa.free(bytes);
            const n = try wal_file.readAll(bytes);
            if (n != bytes.len) return error.Corrupt;
            var pos: usize = 0;
            while (pos < bytes.len) {
                const dec = decodeRecord(bytes[pos..]) catch return error.Corrupt;
                try overlayPutRaw(gpa, &overlay, dec.key, dec.op == .tombstone, dec.size, dec.mtime_ns, dec.etag);
                pos += dec.consumed;
            }
        }
    }
    wal_file.close();

    if (segment == null and wal_size == 0) {
        // Directory exists but has neither a segment nor any WAL entries —
        // our own bootstrap always writes at least an (empty) segment, so
        // this state is anomalous. Treat as missing/corrupt and rebuild.
        for (overlay.items) |e| {
            gpa.free(e.key);
            gpa.free(e.etag);
        }
        overlay.deinit(gpa);
        return error.Corrupt;
    }

    // Reopen the WAL as the long-lived append handle (write-only is enough;
    // reads above used a short-lived handle already closed).
    const wal_write = try idx_dir.createFile(wal_name, .{ .truncate = false });

    return .{
        .gpa = gpa,
        .bucket_dir = bucket_dir,
        .idx_dir = idx_dir,
        .wal_file = wal_write,
        .wal_write_pos = wal_size,
        .overlay = overlay,
        .segment = segment,
        .seg_counter = seg_num_found,
        .compact_threshold = threshold,
    };
}

fn openOrBootstrap(gpa: Allocator, data_dir: Dir, bucket: []const u8, threshold: usize) !BucketIndex {
    var bucket_dir = try data_dir.openDir(bucket, .{ .iterate = true });
    errdefer bucket_dir.close();

    if (tryOpenExisting(gpa, bucket_dir, threshold)) |bi| {
        return bi;
    } else |err| {
        std.log.info("index: (re)building bucket={s} reason={s}", .{ bucket, @errorName(err) });
        bucket_dir.deleteTree(index_dir_name) catch {};
        return bootstrapBuild(gpa, bucket_dir, threshold);
    }
}

// ── Manager: process-global registry of per-bucket indexes. ──

pub const Manager = struct {
    gpa: Allocator,
    data_dir: Dir,
    mutex: std.Thread.Mutex = .{},
    buckets: std.StringHashMap(*BucketIndex),
    /// Overlay size (entry count) at which a bucket auto-compacts. Public
    /// and mutable so tests can force frequent compaction.
    compact_threshold: usize = compact_threshold_default,

    pub fn init(gpa: Allocator, data_dir: Dir) Manager {
        return .{ .gpa = gpa, .data_dir = data_dir, .buckets = std.StringHashMap(*BucketIndex).init(gpa) };
    }

    pub fn deinit(self: *Manager) void {
        var it = self.buckets.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.*.deinit();
            self.gpa.destroy(kv.value_ptr.*);
            self.gpa.free(kv.key_ptr.*);
        }
        self.buckets.deinit();
    }

    fn getOrOpen(self: *Manager, bucket: []const u8) !*BucketIndex {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.buckets.get(bucket)) |bi| return bi;

        const bi = try self.gpa.create(BucketIndex);
        errdefer self.gpa.destroy(bi);
        bi.* = try openOrBootstrap(self.gpa, self.data_dir, bucket, self.compact_threshold);
        errdefer bi.deinit();

        const key_owned = try self.gpa.dupe(u8, bucket);
        errdefer self.gpa.free(key_owned);
        try self.buckets.put(key_owned, bi);
        return bi;
    }

    /// List a bucket's objects via the index. Propagates errors so the
    /// caller can fall back to the FS-walk listing.
    pub fn list(self: *Manager, allocator: Allocator, bucket: []const u8, opts: ListOpts) !ListPage {
        const bi = try self.getOrOpen(bucket);
        return bi.list(allocator, opts);
    }

    /// Never fails the request path — logs and drops the update on error.
    pub fn noteUpsert(self: *Manager, bucket: []const u8, key: []const u8, size: u64, mtime_ns: i128, etag: []const u8) void {
        const bi = self.getOrOpen(bucket) catch |e| {
            std.log.warn("index: noteUpsert open bucket={s} failed: {}", .{ bucket, e });
            return;
        };
        bi.upsert(key, size, mtime_ns, etag) catch |e| {
            std.log.warn("index: noteUpsert bucket={s} key={s} failed: {}", .{ bucket, key, e });
        };
    }

    /// Never fails the request path — logs and drops the update on error.
    pub fn noteDelete(self: *Manager, bucket: []const u8, key: []const u8) void {
        const bi = self.getOrOpen(bucket) catch |e| {
            std.log.warn("index: noteDelete open bucket={s} failed: {}", .{ bucket, e });
            return;
        };
        bi.remove(key) catch |e| {
            std.log.warn("index: noteDelete bucket={s} key={s} failed: {}", .{ bucket, key, e });
        };
    }

    /// Drop a bucket's in-memory state and on-disk index directory. Called
    /// when the bucket itself is deleted; best-effort, never fails.
    pub fn dropBucket(self: *Manager, bucket: []const u8) void {
        self.mutex.lock();
        var loaded: ?*BucketIndex = null;
        if (self.buckets.fetchRemove(bucket)) |kv| {
            loaded = kv.value;
            self.gpa.free(kv.key);
        }
        self.mutex.unlock();

        if (loaded) |bi| {
            bi.closeHandlesAndDeleteOnDisk();
            self.gpa.destroy(bi);
        } else {
            var bd = self.data_dir.openDir(bucket, .{}) catch return;
            defer bd.close();
            bd.deleteTree(index_dir_name) catch |e| {
                std.log.warn("index: dropBucket (unloaded) deleteTree bucket={s} failed: {}", .{ bucket, e });
            };
        }
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "record encode/decode round trip incl. tombstone and max-len key" {
    const a = testing.allocator;

    const rec: Record = .{ .op = .upsert, .key = "hello/world.txt", .size = 1234, .mtime_ns = 9_999_999_999, .etag = "deadbeef" };
    const bytes = try encodeRecord(a, rec);
    defer a.free(bytes);
    const dec = try decodeRecord(bytes);
    try testing.expectEqual(dec.consumed, bytes.len);
    try testing.expectEqual(Op.upsert, dec.op);
    try testing.expectEqualStrings(rec.key, dec.key);
    try testing.expectEqual(rec.size, dec.size);
    try testing.expectEqual(rec.mtime_ns, dec.mtime_ns);
    try testing.expectEqualStrings(rec.etag, dec.etag);

    const tomb: Record = .{ .op = .tombstone, .key = "gone.txt", .size = 0, .mtime_ns = 0, .etag = "" };
    const tbytes = try encodeRecord(a, tomb);
    defer a.free(tbytes);
    const tdec = try decodeRecord(tbytes);
    try testing.expectEqual(Op.tombstone, tdec.op);
    try testing.expectEqualStrings("gone.txt", tdec.key);
    try testing.expectEqualStrings("", tdec.etag);

    // Max-length key (S3 limit).
    const big_key = try a.alloc(u8, util.max_key_length);
    defer a.free(big_key);
    @memset(big_key, 'k');
    const big: Record = .{ .op = .upsert, .key = big_key, .size = 42, .mtime_ns = 1, .etag = "abc123" };
    const bbytes = try encodeRecord(a, big);
    defer a.free(bbytes);
    const bdec = try decodeRecord(bbytes);
    try testing.expectEqualStrings(big_key, bdec.key);

    // Two consecutive records decode correctly back to back.
    var concat = std.ArrayList(u8){};
    defer concat.deinit(a);
    try concat.appendSlice(a, bytes);
    try concat.appendSlice(a, tbytes);
    const first = try decodeRecord(concat.items);
    try testing.expectEqualStrings("hello/world.txt", first.key);
    const second = try decodeRecord(concat.items[first.consumed..]);
    try testing.expectEqualStrings("gone.txt", second.key);
}

const PageTotals = struct { objects: usize, cps: usize };

/// Paginate both the index and the FS-walk listing with the same opts,
/// asserting page-for-page equality (keys, etags, sizes, common prefixes,
/// truncation) plus strictly-ascending keys across page boundaries (no
/// duplicates, no gaps). Returns the totals so callers can assert zero loss.
fn expectPagesEqual(a: Allocator, data_dir: Dir, mgr: *Manager, bucket: []const u8, prefix: []const u8, delimiter: []const u8, max_keys: usize) !PageTotals {
    var totals: PageTotals = .{ .objects = 0, .cps = 0 };
    var cont: []const u8 = "";
    var walk_cont: []const u8 = "";
    var cont_buf: ?[]u8 = null;
    var walk_cont_buf: ?[]u8 = null;
    defer if (cont_buf) |b| a.free(b);
    defer if (walk_cont_buf) |b| a.free(b);
    var last_key_buf: [util.max_key_length]u8 = undefined;
    var last_key: []const u8 = "";
    var last_cp_buf: [util.max_key_length]u8 = undefined;
    var last_cp: []const u8 = "";
    var page_no: usize = 0;
    while (true) {
        page_no += 1;
        const idx_page = try mgr.list(a, bucket, .{ .prefix = prefix, .delimiter = delimiter, .continuation_token = cont, .max_keys = max_keys });
        defer freePage(a, idx_page);
        const fs_page = try @import("storage/objects.zig").listObjects(data_dir, a, bucket, .{ .prefix = prefix, .delimiter = delimiter, .continuation_token = walk_cont, .max_keys = max_keys });
        defer freePage(a, fs_page);

        try testing.expectEqual(fs_page.objects.len, idx_page.objects.len);
        for (fs_page.objects, idx_page.objects) |fo, io| {
            try testing.expectEqualStrings(fo.key, io.key);
            try testing.expectEqualStrings(fo.etag, io.etag);
            try testing.expectEqual(fo.size, io.size);
        }
        try testing.expectEqual(fs_page.common_prefixes.len, idx_page.common_prefixes.len);
        for (fs_page.common_prefixes, idx_page.common_prefixes) |fp, ip| {
            try testing.expectEqualStrings(fp, ip);
        }
        try testing.expectEqual(fs_page.is_truncated, idx_page.is_truncated);

        // Zero-loss invariants across page boundaries: object keys strictly
        // ascending (no dupes/gaps), common prefixes never re-emitted.
        for (idx_page.objects) |o| {
            if (last_key.len > 0) try testing.expect(std.mem.lessThan(u8, last_key, o.key));
            @memcpy(last_key_buf[0..o.key.len], o.key);
            last_key = last_key_buf[0..o.key.len];
        }
        for (idx_page.common_prefixes) |cp| {
            if (last_cp.len > 0) try testing.expect(std.mem.lessThan(u8, last_cp, cp));
            @memcpy(last_cp_buf[0..cp.len], cp);
            last_cp = last_cp_buf[0..cp.len];
        }
        totals.objects += idx_page.objects.len;
        totals.cps += idx_page.common_prefixes.len;

        if (!fs_page.is_truncated) break;
        // `idx_page`/`fs_page` (and their next_continuation_token slices) are
        // freed at the end of this iteration — dupe before that happens.
        const new_cont = try a.dupe(u8, idx_page.next_continuation_token);
        if (cont_buf) |b| a.free(b);
        cont_buf = new_cont;
        cont = new_cont;
        const new_walk_cont = try a.dupe(u8, fs_page.next_continuation_token);
        if (walk_cont_buf) |b| a.free(b);
        walk_cont_buf = new_walk_cont;
        walk_cont = new_walk_cont;
        // Bound runaway loops in case of a bug.
        if (page_no > 600) return error.TooManyPages;
    }
    return totals;
}

fn freePage(a: Allocator, p: ListPage) void {
    for (p.objects) |o| {
        a.free(o.key);
        a.free(o.last_modified);
        a.free(o.etag);
    }
    a.free(p.objects);
    for (p.common_prefixes) |cp| a.free(cp);
    a.free(p.common_prefixes);
    if (p.next_continuation_token.len > 0) a.free(p.next_continuation_token);
}

test "upsert/list equivalence against storage.listObjects" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    const objects = @import("storage/objects.zig");
    try buckets.createBucket(tmp.dir, "eqv");

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();

    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var key_buf: [64]u8 = undefined;
        const bucket_no = rnd.intRangeAtMost(u32, 0, 4);
        const key = try std.fmt.bufPrint(&key_buf, "a/{d}/obj-{d:0>5}.txt", .{ bucket_no, i });
        var fbs = std.Io.Reader.fixed("payload");
        const meta = try objects.putObjectStreaming(tmp.dir, a, .{ .bucket = "eqv", .key = key, .content_length = 7, .content_type = "text/plain" }, &fbs);
        a.free(meta.content_type);
        a.free(meta.etag);
    }
    // Root-level keys so delimiter listings mix objects and common prefixes.
    while (i < 510) : (i += 1) {
        var key_buf: [64]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buf, "root-{d:0>2}.txt", .{i - 500});
        var fbs = std.Io.Reader.fixed("payload");
        const meta = try objects.putObjectStreaming(tmp.dir, a, .{ .bucket = "eqv", .key = key, .content_length = 7, .content_type = "text/plain" }, &fbs);
        a.free(meta.content_type);
        a.free(meta.etag);
    }

    var mgr = Manager.init(a, tmp.dir);
    defer mgr.deinit();

    // Full pagination: zero loss — exactly 510 keys, in order, no dupes/gaps.
    const t_all = try expectPagesEqual(a, tmp.dir, &mgr, "eqv", "", "", 100);
    try testing.expectEqual(@as(usize, 510), t_all.objects);
    try testing.expectEqual(@as(usize, 0), t_all.cps);

    // Delimiter roll-up: 5 common prefixes (a/0/..a/4/), no objects.
    const t_cp = try expectPagesEqual(a, tmp.dir, &mgr, "eqv", "a/", "/", 100);
    try testing.expectEqual(@as(usize, 0), t_cp.objects);
    try testing.expectEqual(@as(usize, 5), t_cp.cps);

    // Page boundary INSIDE a delimiter group: max_keys=2 forces truncation
    // where next_token is the first key of the next cp group; resuming AT it
    // must not drop or re-emit any prefix.
    const t_cp_small = try expectPagesEqual(a, tmp.dir, &mgr, "eqv", "a/", "/", 2);
    try testing.expectEqual(@as(usize, 0), t_cp_small.objects);
    try testing.expectEqual(@as(usize, 5), t_cp_small.cps);

    // Mixed objects + common prefix with truncation across both kinds.
    const t_mix = try expectPagesEqual(a, tmp.dir, &mgr, "eqv", "", "/", 3);
    try testing.expectEqual(@as(usize, 10), t_mix.objects);
    try testing.expectEqual(@as(usize, 1), t_mix.cps);

    // Prefix-scoped pagination (no delimiter) still page-for-page identical.
    const t_pfx = try expectPagesEqual(a, tmp.dir, &mgr, "eqv", "a/0/", "", 50);
    try testing.expectEqual(@as(usize, 0), t_pfx.cps);
}

test "overlay semantics: delete then re-upsert" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    const objects = @import("storage/objects.zig");
    try buckets.createBucket(tmp.dir, "ovl");

    var fbs1 = std.Io.Reader.fixed("hello");
    const m1 = try objects.putObjectStreaming(tmp.dir, a, .{ .bucket = "ovl", .key = "seg-key.txt", .content_length = 5, .content_type = "text/plain" }, &fbs1);
    a.free(m1.content_type);
    a.free(m1.etag);

    var mgr = Manager.init(a, tmp.dir);
    defer mgr.deinit();

    // Force the index to bootstrap now, so "seg-key.txt" lives in the
    // on-disk segment (not the overlay) before we mutate it.
    {
        const p = try mgr.list(a, "ovl", .{});
        freePage(a, p);
    }

    // Upsert a brand-new key (only ever in the overlay), delete it, list
    // should omit it.
    mgr.noteUpsert("ovl", "overlay-only.txt", 10, 111, "etagA");
    mgr.noteDelete("ovl", "overlay-only.txt");
    {
        const p = try mgr.list(a, "ovl", .{});
        defer freePage(a, p);
        for (p.objects) |o| try testing.expect(!std.mem.eql(u8, o.key, "overlay-only.txt"));
    }

    // Tombstone a segment-resident key via the WAL; list omits it.
    mgr.noteDelete("ovl", "seg-key.txt");
    {
        const p = try mgr.list(a, "ovl", .{});
        defer freePage(a, p);
        for (p.objects) |o| try testing.expect(!std.mem.eql(u8, o.key, "seg-key.txt"));
    }

    // Re-upsert after delete: key reappears with the new etag/size.
    mgr.noteUpsert("ovl", "seg-key.txt", 99, 222, "etagB");
    {
        const p = try mgr.list(a, "ovl", .{});
        defer freePage(a, p);
        var found = false;
        for (p.objects) |o| {
            if (std.mem.eql(u8, o.key, "seg-key.txt")) {
                found = true;
                try testing.expectEqual(@as(u64, 99), o.size);
                try testing.expectEqualStrings("\"etagB\"", o.etag);
            }
        }
        try testing.expect(found);
    }
}

test "compaction merges overlay+segment, drops tombstones, truncates WAL" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    try buckets.createBucket(tmp.dir, "cpt");

    var mgr = Manager.init(a, tmp.dir);
    mgr.compact_threshold = 10; // force frequent compaction for the test
    defer mgr.deinit();

    // Bootstrap on an empty bucket.
    {
        const p = try mgr.list(a, "cpt", .{});
        freePage(a, p);
    }

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 25) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "k-{d:0>4}", .{i});
        mgr.noteUpsert("cpt", key, i, @intCast(i), "et");
    }
    // Delete a few keys that should never reappear after compaction.
    mgr.noteDelete("cpt", "k-0003");
    mgr.noteDelete("cpt", "k-0010");

    const p = try mgr.list(a, "cpt", .{ .max_keys = 1000 });
    defer freePage(a, p);
    try testing.expectEqual(@as(usize, 23), p.objects.len);
    for (p.objects) |o| {
        try testing.expect(!std.mem.eql(u8, o.key, "k-0003"));
        try testing.expect(!std.mem.eql(u8, o.key, "k-0010"));
    }

    // Exactly one segment file should exist on disk, and the WAL should be
    // empty (compaction ran and truncated it; the deletes above landed after
    // the last auto-compaction, so re-check state directly).
    var idx_dir = try tmp.dir.openDir("cpt/" ++ index_dir_name, .{ .iterate = true });
    defer idx_dir.close();
    var seg_count: usize = 0;
    {
        var it = idx_dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.startsWith(u8, entry.name, "seg-") and std.mem.endsWith(u8, entry.name, ".idx")) seg_count += 1;
        }
    }
    try testing.expect(seg_count >= 1);
    // With threshold=10 and 25 upserts + 2 deletes (27 WAL appends total),
    // at least one compaction must have occurred.
    try testing.expect(seg_count == 1);
}

test "corrupted segment triggers self-healing rebuild" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    const objects = @import("storage/objects.zig");
    try buckets.createBucket(tmp.dir, "corrupt");

    var fbs = std.Io.Reader.fixed("data");
    const m = try objects.putObjectStreaming(tmp.dir, a, .{ .bucket = "corrupt", .key = "file.txt", .content_length = 4, .content_type = "text/plain" }, &fbs);
    a.free(m.content_type);
    a.free(m.etag);

    {
        var mgr = Manager.init(a, tmp.dir);
        defer mgr.deinit();
        const p = try mgr.list(a, "corrupt", .{});
        freePage(a, p);
    }

    // Truncate the segment file mid-record to simulate corruption.
    {
        var idx_dir = try tmp.dir.openDir("corrupt/" ++ index_dir_name, .{});
        defer idx_dir.close();
        var f = try idx_dir.openFile("seg-00000001.idx", .{ .mode = .read_write });
        defer f.close();
        try f.setEndPos(14); // chop off well before the trailer
    }

    var mgr2 = Manager.init(a, tmp.dir);
    defer mgr2.deinit();
    // Must not propagate a corruption error to the caller — self-heals via
    // rebuild instead.
    const p2 = try mgr2.list(a, "corrupt", .{});
    defer freePage(a, p2);
    try testing.expectEqual(@as(usize, 1), p2.objects.len);
    try testing.expectEqualStrings("file.txt", p2.objects[0].key);
}

test "sparse footer seek returns correct window on a large synthetic segment" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const buckets = @import("storage/buckets.zig");
    try buckets.createBucket(tmp.dir, "big");

    var bucket_dir = try tmp.dir.openDir("big", .{ .iterate = true });
    defer bucket_dir.close();
    try bucket_dir.makeDir(index_dir_name);
    var idx_dir = try bucket_dir.openDir(index_dir_name, .{ .iterate = true });
    defer idx_dir.close();

    // Write 10k synthetic sorted records directly (no real objects needed —
    // sparse-footer correctness only depends on the segment's byte layout).
    const n: usize = 10_000;
    {
        var seg_file = try idx_dir.createFile("seg-00000001.idx.tmp", .{ .truncate = true });
        var write_buf: [64 * 1024]u8 = undefined;
        var fw = seg_file.writer(&write_buf);
        const w = &fw.interface;
        try writeSegHeader(w);

        var footer = std.ArrayList(FooterEntry){};
        defer {
            for (footer.items) |f| a.free(f.key);
            footer.deinit(a);
        }
        var count: u64 = 0;
        var offset: u64 = 12;
        var i: usize = 0;
        var kb: [16]u8 = undefined;
        while (i < n) : (i += 1) {
            const key = try std.fmt.bufPrint(&kb, "key-{d:0>6}", .{i});
            try writeRecordAndTrack(w, a, &footer, &count, &offset, key, i, @intCast(i), "e");
        }
        try writeSegTrailer(w, &footer, offset);
        try w.flush();
        try patchRecordCountAndFinish(&seg_file, count);
        seg_file.close();
        try idx_dir.rename("seg-00000001.idx.tmp", "seg-00000001.idx");
    }
    var wal_file = try idx_dir.createFile(wal_name, .{ .truncate = true });
    wal_file.close();

    var mgr = Manager.init(a, tmp.dir);
    defer mgr.deinit();

    // Prefix window in the middle of the key space.
    const p = try mgr.list(a, "big", .{ .prefix = "key-005", .max_keys = 1000 });
    defer freePage(a, p);
    try testing.expectEqual(@as(usize, 1000), p.objects.len); // key-005000..key-005999
    try testing.expectEqualStrings("key-005000", p.objects[0].key);
    try testing.expectEqualStrings("key-005999", p.objects[p.objects.len - 1].key);

    // Full listing paginated at max_keys=100 must recover exactly n keys,
    // strictly ascending across page boundaries — zero loss, no duplicates,
    // no gaps (continuation_token is inclusive: resume AT the first
    // unemitted key).
    var seen: usize = 0;
    var pages: usize = 0;
    var cont: []const u8 = "";
    var cont_buf: ?[]u8 = null;
    defer if (cont_buf) |b| a.free(b);
    var last_key_buf: [64]u8 = undefined;
    var last_key: []const u8 = "";
    while (true) {
        const page = try mgr.list(a, "big", .{ .continuation_token = cont, .max_keys = 100 });
        defer freePage(a, page);
        for (page.objects) |o| {
            if (last_key.len > 0) try testing.expect(std.mem.lessThan(u8, last_key, o.key));
            @memcpy(last_key_buf[0..o.key.len], o.key);
            last_key = last_key_buf[0..o.key.len];
        }
        seen += page.objects.len;
        pages += 1;
        if (!page.is_truncated) break;
        const new_cont = try a.dupe(u8, page.next_continuation_token);
        if (cont_buf) |b| a.free(b);
        cont_buf = new_cont;
        cont = new_cont;
        if (pages > n) return error.TooManyPages;
    }
    try testing.expectEqual(n, seen);
    try testing.expectEqualStrings("key-009999", last_key);
}
