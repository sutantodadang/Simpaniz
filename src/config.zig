//! Simpaniz server configuration.
//! Loaded from environment variables with sensible defaults.
//! Strings are owned by an internal arena freed on deinit().
const std = @import("std");
const Allocator = std.mem.Allocator;

const Self = @This();

arena: std.heap.ArenaAllocator,

host: []const u8,
port: u16,
data_dir: []const u8,
region: []const u8,
access_key: []const u8,
secret_key: []const u8,
/// Maximum allowed request body size in bytes (single-part PUT).
max_body_bytes: u64,
/// Per-connection idle timeout in milliseconds (keep-alive idle).
idle_timeout_ms: u32,
/// Per-request read timeout in milliseconds.
read_timeout_ms: u32,
/// Maximum size of a single HTTP header line in bytes.
max_header_bytes: usize,
/// Maximum number of headers per request.
max_headers: usize,
/// Allow anonymous access when access_key is empty.
auth_required: bool,
/// Master key for SSE-S3, decoded from `SIMPANIZ_MASTER_KEY` (base64 32 bytes).
/// Empty (`master_key_set == false`) → SSE requests are rejected with 501.
master_key: [32]u8,
master_key_set: bool,
/// Maximum number of concurrent connections (worker threads in flight).
/// Excess connections are accepted-and-rejected with 503.
max_conns: u32,
/// Background bitrot scrub interval in seconds. 0 disables.
scrub_interval_s: u64,
/// Background lifecycle sweep interval in seconds. 0 disables.
lifecycle_interval_s: u64,
/// Background self-heal interval in seconds (cluster mode only). 0 disables.
heal_interval_s: u64,
/// Path to TLS certificate (PEM). If set, server warns and refuses to start
/// because in-process TLS is not yet implemented; terminate at a reverse
/// proxy (nginx/caddy/haproxy) instead. See SECURITY.md.
tls_cert_path: []const u8,
/// Path to TLS private key (PEM). See `tls_cert_path`.
tls_key_path: []const u8,
/// Domain name for zero-config ACME (Let's Encrypt) certificate issuance and
/// auto-renewal. Mutually exclusive with `tls_cert_path`/`tls_key_path`
/// (checked in `main.zig`, same style as the cert/key pairing check).
tls_acme_domain: []const u8 = "",
/// ACME directory URL. Defaults to Let's Encrypt production.
acme_directory_url: []const u8 = "https://acme-v02.api.letsencrypt.org/directory",
/// Optional ACME account contact, e.g. `mailto:ops@example.com`.
acme_contact: []const u8 = "",
/// Port the HTTP-01 challenge listener binds while proving domain control.
acme_http_port: u16 = 80,
/// When true, a GET on a tiered (cold) object rehydrates it: the fetched
/// bytes are written back to hot storage and the cold copy is removed.
/// Default false (GET stays a transparent, non-mutating read).
tier_rehydrate: bool = false,

/// Load configuration from environment variables. Caller must call `deinit`.
pub fn load(allocator: Allocator) Self {
    var arena = std.heap.ArenaAllocator.init(allocator);
    const a = arena.allocator();
    const access_key = getEnv(a, "SIMPANIZ_ACCESS_KEY", "");
    const mk_b64 = getEnv(a, "SIMPANIZ_MASTER_KEY", "");
    var mk: [32]u8 = .{0} ** 32;
    var mk_set = false;
    if (mk_b64.len > 0) {
        const dec = std.base64.standard.Decoder;
        const decoded_len = dec.calcSizeForSlice(mk_b64) catch 0;
        if (decoded_len == 32) {
            dec.decode(&mk, mk_b64) catch {
                std.log.err("SIMPANIZ_MASTER_KEY: invalid base64; SSE disabled", .{});
            };
            mk_set = true;
        } else {
            std.log.err("SIMPANIZ_MASTER_KEY must decode to 32 bytes (got {d}); SSE disabled", .{decoded_len});
        }
    }
    return .{
        .arena = arena,
        .host = getEnv(a, "SIMPANIZ_HOST", "0.0.0.0"),
        .port = getEnvU16(a, "SIMPANIZ_PORT", 9000),
        .data_dir = getEnv(a, "SIMPANIZ_DATA_DIR", "./data"),
        .region = getEnv(a, "SIMPANIZ_REGION", "us-east-1"),
        .access_key = access_key,
        .secret_key = getEnv(a, "SIMPANIZ_SECRET_KEY", ""),
        .max_body_bytes = getEnvU64(a, "SIMPANIZ_MAX_BODY_BYTES", 5 * 1024 * 1024 * 1024), // 5 GiB
        .idle_timeout_ms = @intCast(getEnvU64(a, "SIMPANIZ_IDLE_TIMEOUT_MS", 60_000)),
        .read_timeout_ms = @intCast(getEnvU64(a, "SIMPANIZ_READ_TIMEOUT_MS", 30_000)),
        .max_header_bytes = @intCast(getEnvU64(a, "SIMPANIZ_MAX_HEADER_BYTES", 16 * 1024)),
        .max_headers = @intCast(getEnvU64(a, "SIMPANIZ_MAX_HEADERS", 64)),
        .max_conns = @intCast(getEnvU64(a, "SIMPANIZ_MAX_CONNS", 256)),
        .scrub_interval_s = getEnvU64(a, "SIMPANIZ_SCRUB_INTERVAL_S", 0),
        .lifecycle_interval_s = getEnvU64(a, "SIMPANIZ_LIFECYCLE_INTERVAL_S", 0),
        .heal_interval_s = getEnvU64(a, "SIMPANIZ_HEAL_INTERVAL_S", 0),
        .master_key = mk,
        .master_key_set = mk_set,
        .auth_required = access_key.len > 0,
        .tls_cert_path = getEnv(a, "SIMPANIZ_TLS_CERT", ""),
        .tls_key_path = getEnv(a, "SIMPANIZ_TLS_KEY", ""),
        .tls_acme_domain = getEnv(a, "SIMPANIZ_TLS_ACME", ""),
        .acme_directory_url = getEnv(a, "SIMPANIZ_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
        .acme_contact = getEnv(a, "SIMPANIZ_ACME_CONTACT", ""),
        .acme_http_port = getEnvU16(a, "SIMPANIZ_ACME_HTTP_PORT", 80),
        .tier_rehydrate = getEnvBool(a, "SIMPANIZ_TIER_REHYDRATE", false),
    };
}

pub fn deinit(self: *Self) void {
    self.arena.deinit();
}

fn getEnv(a: Allocator, key: []const u8, default: []const u8) []const u8 {
    return std.process.getEnvVarOwned(a, key) catch a.dupe(u8, default) catch default;
}

fn getEnvU16(a: Allocator, key: []const u8, default: u16) u16 {
    const s = std.process.getEnvVarOwned(a, key) catch return default;
    return std.fmt.parseInt(u16, s, 10) catch default;
}

fn getEnvU64(a: Allocator, key: []const u8, default: u64) u64 {
    const s = std.process.getEnvVarOwned(a, key) catch return default;
    return std.fmt.parseInt(u64, s, 10) catch default;
}

fn getEnvBool(a: Allocator, key: []const u8, default: bool) bool {
    const s = std.process.getEnvVarOwned(a, key) catch return default;
    return std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "true") or std.ascii.eqlIgnoreCase(s, "yes");
}

pub fn listenAddress(self: *const Self, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.host, self.port }) catch "0.0.0.0:9000";
}
