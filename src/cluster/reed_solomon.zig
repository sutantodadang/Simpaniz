//! Reed-Solomon erasure coding over GF(256).
//!
//! Generates `m` parity shards from `k` data shards. Any `k` of the
//! resulting `k + m` shards are sufficient to reconstruct the original
//! `k` data shards.
//!
//! The encoding matrix `E` is `(k+m) × k`:
//!   - rows 0..k     identity (data shards are systematic)
//!   - rows k..k+m   Vandermonde with generators 1..m
//!
//! All arithmetic is in GF(256) with primitive polynomial `0x11d`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_shards: usize = 32;

// ── GF(256) tables ──────────────────────────────────────────────────────────

var gf_exp: [512]u8 = undefined;
var gf_log: [256]u8 = undefined;
var gf_initialized: bool = false;

fn gfInit() void {
    if (gf_initialized) return;
    var x: u32 = 1;
    for (0..255) |i| {
        gf_exp[i] = @intCast(x);
        gf_log[x] = @intCast(i);
        x <<= 1;
        if (x & 0x100 != 0) x ^= 0x11d;
    }
    for (255..512) |i| gf_exp[i] = gf_exp[i - 255];
    gf_initialized = true;
}

inline fn gfAdd(a: u8, b: u8) u8 {
    return a ^ b;
}

inline fn gfMul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    return gf_exp[@as(usize, gf_log[a]) + @as(usize, gf_log[b])];
}

inline fn gfInv(a: u8) u8 {
    std.debug.assert(a != 0);
    return gf_exp[255 - @as(usize, gf_log[a])];
}

// ── Matrix helpers ──────────────────────────────────────────────────────────

const Matrix = struct {
    rows: usize,
    cols: usize,
    data: []u8,

    fn at(self: Matrix, r: usize, c: usize) u8 {
        return self.data[r * self.cols + c];
    }
    fn set(self: Matrix, r: usize, c: usize, v: u8) void {
        self.data[r * self.cols + c] = v;
    }

    fn alloc(allocator: Allocator, rows: usize, cols: usize) !Matrix {
        const buf = try allocator.alloc(u8, rows * cols);
        @memset(buf, 0);
        return .{ .rows = rows, .cols = cols, .data = buf };
    }
    fn free(self: Matrix, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

/// Invert n×n matrix in place using Gauss-Jordan over GF(256).
fn invert(m: Matrix) !void {
    std.debug.assert(m.rows == m.cols);
    const n = m.rows;
    var aug_buf: [max_shards * max_shards * 2]u8 = undefined;
    if (n * 2 * n > aug_buf.len) return error.MatrixTooLarge;
    const stride = 2 * n;
    var aug = aug_buf[0 .. n * stride];
    @memset(aug, 0);
    for (0..n) |r| {
        for (0..n) |c| aug[r * stride + c] = m.at(r, c);
        aug[r * stride + n + r] = 1;
    }

    for (0..n) |col| {
        var pivot_row: ?usize = null;
        for (col..n) |r| {
            if (aug[r * stride + col] != 0) {
                pivot_row = r;
                break;
            }
        }
        const pr = pivot_row orelse return error.SingularMatrix;
        if (pr != col) {
            for (0..stride) |c| {
                const tmp = aug[col * stride + c];
                aug[col * stride + c] = aug[pr * stride + c];
                aug[pr * stride + c] = tmp;
            }
        }
        const inv = gfInv(aug[col * stride + col]);
        for (0..stride) |c| aug[col * stride + c] = gfMul(aug[col * stride + c], inv);
        for (0..n) |r| {
            if (r == col) continue;
            const factor = aug[r * stride + col];
            if (factor == 0) continue;
            for (0..stride) |c| {
                const v = gfMul(aug[col * stride + c], factor);
                aug[r * stride + c] = gfAdd(aug[r * stride + c], v);
            }
        }
    }
    for (0..n) |r| for (0..n) |c| {
        m.set(r, c, aug[r * stride + n + c]);
    };
}

// ── Public codec ────────────────────────────────────────────────────────────

pub const Codec = struct {
    k: u8,
    m: u8,
    enc: Matrix,
    allocator: Allocator,

    pub fn init(allocator: Allocator, k: u8, m: u8) !Codec {
        gfInit();
        if (k == 0 or m == 0 or @as(usize, k) + @as(usize, m) > max_shards) {
            return error.InvalidArgument;
        }
        const total: usize = @as(usize, k) + @as(usize, m);
        var enc = try Matrix.alloc(allocator, total, k);
        for (0..k) |i| enc.set(i, i, 1);
        for (0..m) |i| {
            const x: u8 = @intCast(i + 1);
            var pow: u8 = 1;
            for (0..k) |j| {
                enc.set(k + i, j, pow);
                pow = gfMul(pow, x);
            }
        }
        return .{ .k = k, .m = m, .enc = enc, .allocator = allocator };
    }

    pub fn deinit(self: *Codec) void {
        self.enc.free(self.allocator);
    }

    pub fn shardCount(self: Codec) usize {
        return @as(usize, self.k) + @as(usize, self.m);
    }

    pub fn encode(
        self: Codec,
        data_shards: []const []const u8,
        parity_shards: []const []u8,
    ) !void {
        if (data_shards.len != self.k) return error.InvalidArgument;
        if (parity_shards.len != self.m) return error.InvalidArgument;
        if (self.k == 0) return;
        const sz = data_shards[0].len;
        for (data_shards) |d| if (d.len != sz) return error.InvalidArgument;
        for (parity_shards) |p| if (p.len != sz) return error.InvalidArgument;

        for (0..self.m) |i| {
            const out = parity_shards[i];
            @memset(out, 0);
            for (0..self.k) |j| {
                const coeff = self.enc.at(self.k + i, j);
                if (coeff == 0) continue;
                const src = data_shards[j];
                for (0..sz) |b| out[b] = gfAdd(out[b], gfMul(coeff, src[b]));
            }
        }
    }

    /// Reconstruct missing data shards. `present` is `[k+m]?[]const u8`,
    /// `null` for missing. At least `k` entries must be non-null.
    /// `out_data[d]` is filled for each missing data shard `d`; entries
    /// already present are left untouched.
    pub fn reconstructData(
        self: Codec,
        present: []const ?[]const u8,
        out_data: []const []u8,
    ) !void {
        const total = self.shardCount();
        if (present.len != total) return error.InvalidArgument;
        if (out_data.len != self.k) return error.InvalidArgument;

        var picked: [max_shards]usize = undefined;
        var n_picked: usize = 0;
        var sz: usize = 0;
        for (present, 0..) |maybe, idx| {
            if (maybe) |slice| {
                if (n_picked == 0) sz = slice.len;
                if (slice.len != sz) return error.InvalidArgument;
                if (n_picked < self.k) {
                    picked[n_picked] = idx;
                    n_picked += 1;
                }
            }
        }
        if (n_picked < self.k) return error.NotEnoughShards;

        var subA = try Matrix.alloc(self.allocator, self.k, self.k);
        defer subA.free(self.allocator);
        for (0..self.k) |r| for (0..self.k) |c| {
            subA.set(r, c, self.enc.at(picked[r], c));
        };
        try invert(subA);

        for (0..self.k) |d| {
            if (present[d] != null) continue;
            const out = out_data[d];
            if (out.len != sz) return error.InvalidArgument;
            @memset(out, 0);
            for (0..self.k) |r| {
                const coeff = subA.at(d, r);
                if (coeff == 0) continue;
                const src = present[picked[r]].?;
                for (0..sz) |b| out[b] = gfAdd(out[b], gfMul(coeff, src[b]));
            }
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

test "gf256 mul / inv round-trip" {
    gfInit();
    var a: u16 = 1;
    while (a < 256) : (a += 1) {
        const x: u8 = @intCast(a);
        const inv = gfInv(x);
        try std.testing.expectEqual(@as(u8, 1), gfMul(x, inv));
    }
}

test "encode + decode k=4 m=2 with 2 erasures" {
    const allocator = std.testing.allocator;
    var codec = try Codec.init(allocator, 4, 2);
    defer codec.deinit();

    const sz: usize = 64;
    var data_buf: [4][64]u8 = undefined;
    var parity_buf: [2][64]u8 = undefined;
    for (0..4) |i| for (0..sz) |j| {
        data_buf[i][j] = @intCast((i * 17 + j * 31) & 0xFF);
    };

    var data_slices: [4][]const u8 = undefined;
    var parity_slices: [2][]u8 = undefined;
    for (0..4) |i| data_slices[i] = data_buf[i][0..];
    for (0..2) |i| parity_slices[i] = parity_buf[i][0..];

    try codec.encode(&data_slices, &parity_slices);

    var present_arr: [6]?[]const u8 = .{
        null,
        data_buf[1][0..],
        null,
        data_buf[3][0..],
        parity_buf[0][0..],
        parity_buf[1][0..],
    };

    var rec0: [64]u8 = undefined;
    var rec2: [64]u8 = undefined;
    var noop: [64]u8 = undefined;
    var out: [4][]u8 = .{ rec0[0..], noop[0..], rec2[0..], noop[0..] };
    try codec.reconstructData(present_arr[0..], out[0..]);

    try std.testing.expectEqualSlices(u8, &data_buf[0], &rec0);
    try std.testing.expectEqualSlices(u8, &data_buf[2], &rec2);
}

test "decode fails with too few shards" {
    const allocator = std.testing.allocator;
    var codec = try Codec.init(allocator, 4, 2);
    defer codec.deinit();

    const sz: usize = 8;
    var data_buf: [4][8]u8 = undefined;
    var parity_buf: [2][8]u8 = undefined;
    for (0..4) |i| {
        for (0..sz) |j| data_buf[i][j] = @intCast(i + j);
    }
    var ds: [4][]const u8 = undefined;
    var ps: [2][]u8 = undefined;
    for (0..4) |i| ds[i] = data_buf[i][0..];
    for (0..2) |i| ps[i] = parity_buf[i][0..];
    try codec.encode(&ds, &ps);

    var present_arr: [6]?[]const u8 = .{
        null,
        null,
        null,
        data_buf[3][0..],
        parity_buf[0][0..],
        parity_buf[1][0..],
    };
    var bufs: [4][8]u8 = undefined;
    var out: [4][]u8 = .{ bufs[0][0..], bufs[1][0..], bufs[2][0..], bufs[3][0..] };
    try std.testing.expectError(error.NotEnoughShards, codec.reconstructData(present_arr[0..], out[0..]));
}
