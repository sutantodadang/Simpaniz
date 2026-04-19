//! First-run admin credential bootstrap.
//!
//! When neither `SIMPANIZ_ACCESS_KEY` nor `SIMPANIZ_SECRET_KEY` is set in
//! the environment, on first launch we generate a random root credential,
//! persist it to `<data_dir>/.simpaniz-credentials`, and print it
//! prominently to the log so the operator can grab it. Subsequent launches
//! load the same credential from the file. This matches the MinIO
//! "first-run prints the root user" UX so the embedded web console is
//! immediately usable without manual env var fiddling.
const std = @import("std");
const Config = @import("config.zig");

const CREDS_FILE = ".simpaniz-credentials";
const ACCESS_KEY_LEN = 20;
const SECRET_KEY_LEN = 40;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Bootstrap credentials in `config` if none are configured. Mutates
/// `config.access_key`/`config.secret_key` (allocated in `config.arena`)
/// and sets `auth_required=true` when bootstrapping.
pub fn ensureCredentials(config: *Config, data_dir: std.fs.Dir) !void {
    if (config.access_key.len > 0 and config.secret_key.len > 0) return;
    if (config.access_key.len > 0 or config.secret_key.len > 0) {
        std.log.warn("Only one of SIMPANIZ_ACCESS_KEY / SIMPANIZ_SECRET_KEY is set; ignoring partial config and bootstrapping.", .{});
    }

    // Explicit anonymous-mode opt-out for deployments that intentionally
    // run without auth (read-only buckets, dev sandboxes, public mirrors).
    if (anonymousOptIn()) {
        std.log.info("SIMPANIZ_ANONYMOUS set: running without authentication (no root credentials generated).", .{});
        return;
    }

    const a = config.arena.allocator();

    if (try readFile(data_dir, a)) |creds| {
        config.access_key = creds.access;
        config.secret_key = creds.secret;
        config.auth_required = true;
        std.log.info("Loaded admin credentials from <data_dir>/{s} (access_key={s})", .{ CREDS_FILE, creds.access });
        return;
    }

    var ak_buf: [ACCESS_KEY_LEN]u8 = undefined;
    var sk_buf: [SECRET_KEY_LEN]u8 = undefined;
    randomString(&ak_buf);
    randomString(&sk_buf);

    const ak = try a.dupe(u8, &ak_buf);
    const sk = try a.dupe(u8, &sk_buf);

    try writeFile(data_dir, ak, sk);

    config.access_key = ak;
    config.secret_key = sk;
    config.auth_required = true;

    printBanner(ak, sk);
}

const Creds = struct {
    access: []u8,
    secret: []u8,
};

fn readFile(data_dir: std.fs.Dir, a: std.mem.Allocator) !?Creds {
    var file = data_dir.openFile(CREDS_FILE, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();

    var buf: [512]u8 = undefined;
    const n = try file.readAll(&buf);
    const text = std.mem.trim(u8, buf[0..n], " \r\n\t");

    var ak: []const u8 = "";
    var sk: []const u8 = "";
    var iter = std.mem.splitScalar(u8, text, '\n');
    while (iter.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const k = std.mem.trim(u8, line[0..eq], " ");
        const v = std.mem.trim(u8, line[eq + 1 ..], " ");
        if (std.mem.eql(u8, k, "access_key")) ak = v;
        if (std.mem.eql(u8, k, "secret_key")) sk = v;
    }
    if (ak.len == 0 or sk.len == 0) {
        std.log.warn("{s} exists but is missing access_key or secret_key; ignoring.", .{CREDS_FILE});
        return null;
    }
    return .{ .access = try a.dupe(u8, ak), .secret = try a.dupe(u8, sk) };
}

fn writeFile(data_dir: std.fs.Dir, ak: []const u8, sk: []const u8) !void {
    var file = try data_dir.createFile(CREDS_FILE, .{ .mode = 0o600 });
    defer file.close();
    var buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf,
        \\# Simpaniz root credentials — generated on first run.
        \\# To override, set SIMPANIZ_ACCESS_KEY / SIMPANIZ_SECRET_KEY in the environment.
        \\# Keep this file out of source control and 0600-restricted.
        \\access_key={s}
        \\secret_key={s}
        \\
    , .{ ak, sk });
    try file.writeAll(text);
}

fn randomString(out: []u8) void {
    var bytes: [128]u8 = undefined;
    std.crypto.random.bytes(bytes[0..out.len]);
    for (out, 0..) |*c, i| c.* = ALPHABET[bytes[i] % ALPHABET.len];
}

fn anonymousOptIn() bool {
    var buf: [16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const v = std.process.getEnvVarOwned(fba.allocator(), "SIMPANIZ_ANONYMOUS") catch return false;
    return std.mem.eql(u8, v, "1") or
        std.ascii.eqlIgnoreCase(v, "true") or
        std.ascii.eqlIgnoreCase(v, "yes");
}

fn printBanner(ak: []const u8, sk: []const u8) void {
    std.log.info("", .{});
    std.log.info("=====================================================================", .{});
    std.log.info("  Generated root credentials (first run).", .{});
    std.log.info("  Saved to <data_dir>/{s}", .{CREDS_FILE});
    std.log.info("", .{});
    std.log.info("    Access key: {s}", .{ak});
    std.log.info("    Secret key: {s}", .{sk});
    std.log.info("", .{});
    std.log.info("  Sign in at:  http://<host>:<port>/console/", .{});
    std.log.info("=====================================================================", .{});
    std.log.info("", .{});
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "writes and re-reads credentials" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFile(tmp.dir, "AKIAEXAMPLE0000000AB", "secretexamplevalue1234567890ABCDEFGHIJKL");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const got = (try readFile(tmp.dir, arena.allocator())).?;
    try std.testing.expectEqualStrings("AKIAEXAMPLE0000000AB", got.access);
    try std.testing.expectEqualStrings("secretexamplevalue1234567890ABCDEFGHIJKL", got.secret);
}

test "missing file returns null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expect((try readFile(tmp.dir, arena.allocator())) == null);
}

test "randomString fills buffer with alphabet chars" {
    var buf: [40]u8 = undefined;
    randomString(&buf);
    for (buf) |c| {
        try std.testing.expect(std.mem.indexOfScalar(u8, ALPHABET, c) != null);
    }
}
