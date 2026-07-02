//! STS (Security Token Service): AssumeRole (signed, root/IAM caller) and
//! AssumeRoleWithWebIdentity (OIDC JWT → temp creds), plus the in-memory
//! temp-credential store consulted by `server.zig`'s auth path.
//!
//! ponytail: STS credentials are in-memory only; a restart invalidates all
//! outstanding sessions. Roles are a naming ceiling, not an enforcement
//! mechanism — `RoleArn` is accepted and logged but every session is scoped
//! to the caller's own permissions (optionally narrowed by a session policy).
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const xml = @import("xml.zig");
const util = @import("util.zig");
const iam = @import("iam.zig");

// ── Temp credential store ───────────────────────────────────────────────────

pub const TempCred = struct {
    /// "STS" + 17 random alnum chars.
    access_key: [20]u8,
    secret_key: [40]u8,
    /// 43-char random urlsafe token, owned by the store's allocator.
    session_token: []const u8,
    /// Access key of the caller that requested this session (or the OIDC
    /// `sub` claim for AssumeRoleWithWebIdentity), owned.
    base_principal: []const u8,
    is_root_base: bool,
    /// Session policy JSON, owned, or null when no session policy applies.
    session_policy: ?[]const u8,
    expires_unix: i64,
};

const alnum_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn randomAlnum(buf: []u8) void {
    for (buf) |*b| b.* = alnum_chars[std.crypto.random.intRangeLessThan(usize, 0, alnum_chars.len)];
}

pub const StsStore = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMap(*TempCred),

    pub fn init(allocator: Allocator) StsStore {
        return .{ .allocator = allocator, .map = std.StringHashMap(*TempCred).init(allocator) };
    }

    pub fn deinit(self: *StsStore) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.freeCred(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
    }

    fn freeCred(self: *StsStore, cred: *TempCred) void {
        self.allocator.free(cred.session_token);
        self.allocator.free(cred.base_principal);
        if (cred.session_policy) |p| self.allocator.free(p);
        self.allocator.destroy(cred);
    }

    /// Issue a new temporary credential. `duration_s` is clamped to
    /// [900, 43200]; 0 defaults to 3600 (one hour).
    pub fn issue(self: *StsStore, base_principal: []const u8, is_root: bool, session_policy: ?[]const u8, duration_s: u32) !*const TempCred {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.map.count() > 1024) self.sweepExpiredLocked();

        const requested: u32 = if (duration_s == 0) 3600 else duration_s;
        const clamped: u32 = std.math.clamp(requested, @as(u32, 900), @as(u32, 43200));

        const cred = try self.allocator.create(TempCred);
        errdefer self.allocator.destroy(cred);

        cred.access_key[0..3].* = "STS".*;
        randomAlnum(cred.access_key[3..]);
        randomAlnum(&cred.secret_key);

        var token_buf: [43]u8 = undefined;
        randomAlnum(&token_buf);
        cred.session_token = try self.allocator.dupe(u8, &token_buf);
        errdefer self.allocator.free(cred.session_token);

        cred.base_principal = try self.allocator.dupe(u8, base_principal);
        errdefer self.allocator.free(cred.base_principal);

        cred.is_root_base = is_root;
        cred.session_policy = if (session_policy) |p| try self.allocator.dupe(u8, p) else null;
        errdefer if (cred.session_policy) |p| self.allocator.free(p);

        cred.expires_unix = std.time.timestamp() + clamped;

        const key = try self.allocator.dupe(u8, &cred.access_key);
        errdefer self.allocator.free(key);
        try self.map.put(key, cred);

        return cred;
    }

    /// Look up a temp credential by access key + session token. Returns null
    /// on unknown key, expired (evicted lazily), or token mismatch.
    pub fn lookup(self: *StsStore, access_key: []const u8, session_token: []const u8) ?*const TempCred {
        self.mutex.lock();
        defer self.mutex.unlock();

        const cred = self.map.get(access_key) orelse return null;
        if (cred.expires_unix <= std.time.timestamp()) {
            self.removeLocked(access_key);
            return null;
        }
        if (!std.mem.eql(u8, cred.session_token, session_token)) return null;
        return cred;
    }

    fn removeLocked(self: *StsStore, access_key: []const u8) void {
        if (self.map.fetchRemove(access_key)) |kv| {
            self.freeCred(kv.value);
            self.allocator.free(kv.key);
        }
    }

    fn sweepExpiredLocked(self: *StsStore) void {
        const now = std.time.timestamp();
        var expired = std.ArrayList([]const u8){};
        defer expired.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.expires_unix <= now) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (expired.items) |k| self.removeLocked(k);
    }
};

// ── Query-string helper (mirrors the small `qp` in router.zig/handlers.zig) ─

fn qp(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
            if (std.mem.eql(u8, param[0..eq], key)) return param[eq + 1 ..];
        } else if (std.mem.eql(u8, param, key)) {
            return "";
        }
    }
    return null;
}

// ── Response builders ────────────────────────────────────────────────────────

fn statusText(status: u16) []const u8 {
    return switch (status) {
        400 => "Bad Request",
        403 => "Forbidden",
        500 => "Internal Server Error",
        else => "Error",
    };
}

fn errorResponse(allocator: Allocator, status: u16, code: []const u8, message: []const u8, request_id: []const u8) http.Response {
    const body = xml.buildError(allocator, code, message, "/", request_id) catch "";
    return .{ .status = status, .status_text = statusText(status), .body = .{ .bytes = body } };
}

const sts_ns = "https://sts.amazonaws.com/doc/2011-06-15/";

fn buildAssumeRoleXml(allocator: Allocator, root_tag: []const u8, result_tag: []const u8, cred: *const TempCred, request_id: []const u8) http.Response {
    var exp_buf: [40]u8 = undefined;
    const exp_ns: i128 = @as(i128, cred.expires_unix) * std.time.ns_per_s;
    const exp_str = util.formatIso8601(&exp_buf, exp_ns);

    var x = xml.init(allocator);
    defer x.deinit();

    const built: ?[]u8 = blk: {
        x.xmlHeader() catch break :blk null;
        x.openTagNs(root_tag, sts_ns) catch break :blk null;
        x.openTag(result_tag) catch break :blk null;
        x.openTag("Credentials") catch break :blk null;
        x.textElement("AccessKeyId", &cred.access_key) catch break :blk null;
        x.textElement("SecretAccessKey", &cred.secret_key) catch break :blk null;
        x.textElement("SessionToken", cred.session_token) catch break :blk null;
        x.textElement("Expiration", exp_str) catch break :blk null;
        x.closeTag("Credentials") catch break :blk null;
        x.closeTag(result_tag) catch break :blk null;
        x.openTag("ResponseMetadata") catch break :blk null;
        x.textElement("RequestId", request_id) catch break :blk null;
        x.closeTag("ResponseMetadata") catch break :blk null;
        x.closeTag(root_tag) catch break :blk null;
        break :blk x.toOwnedSlice() catch null;
    };
    const body = built orelse return errorResponse(allocator, 500, "InternalError", "Failed to build response.", request_id);
    return .{ .status = 200, .status_text = "OK", .body = .{ .bytes = body } };
}

// ── AssumeRole ───────────────────────────────────────────────────────────────

/// Caller must already be an authenticated (SigV4-verified) principal — root
/// or IAM user. `query` is the raw (undecoded) request query string.
pub fn handleAssumeRole(allocator: Allocator, store: *StsStore, principal: ?iam.Principal, query: []const u8, request_id: []const u8) http.Response {
    const p = principal orelse return errorResponse(allocator, 403, "AccessDenied", "Request must be signed by an authenticated principal.", request_id);

    if (qp(query, "RoleArn")) |arn| {
        std.log.info("sts: AssumeRole RoleArn={s} (single-tenant ceiling: accepted, not enforced)", .{arn});
    }

    const duration_s: u32 = if (qp(query, "DurationSeconds")) |d| (std.fmt.parseInt(u32, d, 10) catch 0) else 0;

    var session_policy: ?[]const u8 = null;
    if (qp(query, "Policy")) |pol_enc| {
        session_policy = util.urlDecode(allocator, pol_enc) catch null;
    }

    const cred = store.issue(p.access_key, p.is_root, session_policy, duration_s) catch
        return errorResponse(allocator, 500, "InternalError", "Failed to issue temporary credentials.", request_id);

    return buildAssumeRoleXml(allocator, "AssumeRoleResponse", "AssumeRoleResult", cred, request_id);
}

// ── AssumeRoleWithWebIdentity ────────────────────────────────────────────────

pub const Jwk = union(enum) {
    rsa: struct { n: []const u8, e: []const u8 },
    ec_p256: EcP256,

    pub const EcP256 = struct { x: [32]u8, y: [32]u8 };
};

pub const OidcConfig = struct {
    allocator: Allocator,
    enabled: bool = false,
    jwks_url: []const u8 = "",
    issuer: []const u8 = "",
    audience: []const u8 = "",
    default_policy_name: []const u8 = "",
    data_dir: std.fs.Dir = undefined,
    keys_mutex: std.Thread.Mutex = .{},
    keys: std.StringHashMap(Jwk),

    /// Loads config from env: SIMPANIZ_OIDC_JWKS_URL (presence enables
    /// OIDC), SIMPANIZ_OIDC_ISSUER (required when enabled),
    /// SIMPANIZ_OIDC_AUDIENCE (optional), SIMPANIZ_OIDC_DEFAULT_POLICY
    /// (optional, names a file under <data_dir>/.simpaniz-iam/policies/).
    pub fn load(gpa: Allocator, data_dir: std.fs.Dir) OidcConfig {
        var self = OidcConfig{ .allocator = gpa, .keys = std.StringHashMap(Jwk).init(gpa), .data_dir = data_dir };

        if (std.process.getEnvVarOwned(gpa, "SIMPANIZ_OIDC_JWKS_URL") catch null) |v| {
            self.jwks_url = v;
            self.enabled = true;
        }
        if (std.process.getEnvVarOwned(gpa, "SIMPANIZ_OIDC_ISSUER") catch null) |v| self.issuer = v;
        if (std.process.getEnvVarOwned(gpa, "SIMPANIZ_OIDC_AUDIENCE") catch null) |v| self.audience = v;
        if (std.process.getEnvVarOwned(gpa, "SIMPANIZ_OIDC_DEFAULT_POLICY") catch null) |v| self.default_policy_name = v;

        if (self.enabled and self.issuer.len == 0) {
            std.log.warn("sts: SIMPANIZ_OIDC_JWKS_URL set but SIMPANIZ_OIDC_ISSUER missing; disabling AssumeRoleWithWebIdentity", .{});
            self.enabled = false;
        }
        return self;
    }

    pub fn deinit(self: *OidcConfig) void {
        if (self.jwks_url.len > 0) self.allocator.free(self.jwks_url);
        if (self.issuer.len > 0) self.allocator.free(self.issuer);
        if (self.audience.len > 0) self.allocator.free(self.audience);
        if (self.default_policy_name.len > 0) self.allocator.free(self.default_policy_name);

        var it = self.keys.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .rsa => |r| {
                    self.allocator.free(r.n);
                    self.allocator.free(r.e);
                },
                .ec_p256 => {},
            }
        }
        self.keys.deinit();
    }
};

pub const Claims = struct {
    sub: []const u8,
    policy_name: ?[]const u8,
};

fn b64UrlDecodeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const len = try decoder.calcSizeForSlice(input);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    try decoder.decode(out, input);
    return out;
}

fn getStr(doc: std.json.Value, field: []const u8) ?[]const u8 {
    if (doc != .object) return null;
    const v = doc.object.get(field) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn getInt(doc: std.json.Value, field: []const u8) ?i64 {
    if (doc != .object) return null;
    const v = doc.object.get(field) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn audienceMatches(doc: std.json.Value, expected: []const u8) bool {
    if (doc != .object) return false;
    const v = doc.object.get("aud") orelse return false;
    return switch (v) {
        .string => |s| std.mem.eql(u8, s, expected),
        .array => |arr| blk: {
            for (arr.items) |item| {
                if (item == .string and std.mem.eql(u8, item.string, expected)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

/// Fetch (or return cached) JWK for `kid`. On cache miss, does a single
/// refetch of the JWKS document before giving up.
/// ponytail: not exercised by tests — offline test suite injects keys
/// directly into `oidc.keys` instead of hitting the network.
fn getKey(oidc: *OidcConfig, scratch: Allocator, kid: []const u8) !Jwk {
    oidc.keys_mutex.lock();
    if (oidc.keys.get(kid)) |k| {
        oidc.keys_mutex.unlock();
        return k;
    }
    oidc.keys_mutex.unlock();

    try fetchJwks(oidc, scratch);

    oidc.keys_mutex.lock();
    defer oidc.keys_mutex.unlock();
    return oidc.keys.get(kid) orelse error.UnknownKid;
}

fn loadJwkFromJson(oidc: *OidcConfig, obj: std.json.ObjectMap, scratch: Allocator) ?struct { kid: []const u8, jwk: Jwk } {
    const kid_v = obj.get("kid") orelse return null;
    if (kid_v != .string) return null;
    const kty_v = obj.get("kty") orelse return null;
    if (kty_v != .string) return null;

    if (std.mem.eql(u8, kty_v.string, "RSA")) {
        const n_v = obj.get("n") orelse return null;
        const e_v = obj.get("e") orelse return null;
        if (n_v != .string or e_v != .string) return null;
        const n_bytes = b64UrlDecodeAlloc(scratch, n_v.string) catch return null;
        const e_bytes = b64UrlDecodeAlloc(scratch, e_v.string) catch return null;
        const n_owned = oidc.allocator.dupe(u8, n_bytes) catch return null;
        const e_owned = oidc.allocator.dupe(u8, e_bytes) catch return null;
        const kid_owned = oidc.allocator.dupe(u8, kid_v.string) catch return null;
        return .{ .kid = kid_owned, .jwk = .{ .rsa = .{ .n = n_owned, .e = e_owned } } };
    } else if (std.mem.eql(u8, kty_v.string, "EC")) {
        const crv_v = obj.get("crv") orelse return null;
        if (crv_v != .string or !std.mem.eql(u8, crv_v.string, "P-256")) return null;
        const x_v = obj.get("x") orelse return null;
        const y_v = obj.get("y") orelse return null;
        if (x_v != .string or y_v != .string) return null;
        const x_bytes = b64UrlDecodeAlloc(scratch, x_v.string) catch return null;
        const y_bytes = b64UrlDecodeAlloc(scratch, y_v.string) catch return null;
        if (x_bytes.len != 32 or y_bytes.len != 32) return null;
        const kid_owned = oidc.allocator.dupe(u8, kid_v.string) catch return null;
        var ec: Jwk.EcP256 = undefined;
        @memcpy(&ec.x, x_bytes);
        @memcpy(&ec.y, y_bytes);
        return .{ .kid = kid_owned, .jwk = .{ .ec_p256 = ec } };
    }
    return null;
}

fn fetchJwks(oidc: *OidcConfig, parent_scratch: Allocator) !void {
    if (oidc.jwks_url.len == 0) return error.NotConfigured;

    var arena = std.heap.ArenaAllocator.init(parent_scratch);
    defer arena.deinit();
    const scratch = arena.allocator();

    var client = std.http.Client{ .allocator = scratch };
    defer client.deinit();
    var aw = std.Io.Writer.Allocating.init(scratch);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = oidc.jwks_url },
        .method = .GET,
        .response_writer = &aw.writer,
        .keep_alive = false,
    }) catch return error.FetchFailed;
    if (@intFromEnum(result.status) < 200 or @intFromEnum(result.status) >= 300) return error.FetchFailed;

    const body = aw.written();
    const doc = std.json.parseFromSliceLeaky(std.json.Value, scratch, body, .{}) catch return error.ParseFailed;
    if (doc != .object) return error.ParseFailed;
    const keys_v = doc.object.get("keys") orelse return error.ParseFailed;
    if (keys_v != .array) return error.ParseFailed;

    oidc.keys_mutex.lock();
    defer oidc.keys_mutex.unlock();
    for (keys_v.array.items) |item| {
        if (item != .object) continue;
        const parsed = loadJwkFromJson(oidc, item.object, scratch) orelse continue;
        oidc.keys.put(parsed.kid, parsed.jwk) catch continue;
    }
}

fn verifyEs256(msg: []const u8, sig_bytes: []const u8, jwk: Jwk) !void {
    if (jwk != .ec_p256) return error.UnsupportedAlg;
    const ec = jwk.ec_p256;
    var sec1: [65]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..33], &ec.x);
    @memcpy(sec1[33..65], &ec.y);

    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const pubkey = Ecdsa.PublicKey.fromSec1(&sec1) catch return error.InvalidKey;
    if (sig_bytes.len != 64) return error.InvalidSignature;
    const sig = Ecdsa.Signature.fromBytes(sig_bytes[0..64].*);
    sig.verify(msg, pubkey) catch return error.InvalidSignature;
}

// ── RSA verify-only: modular exponentiation via std.math.big.int.Managed ────
// No RSA keygen/sign in std, so RS256 is exercised offline via a modexp unit
// test using the classic textbook RSA vector (n=3233, e=17), not a full JWT.

const Managed = std.math.big.int.Managed;

fn managedFromBytes(allocator: Allocator, bytes: []const u8) !Managed {
    var hex = try allocator.alloc(u8, bytes.len * 2);
    defer allocator.free(hex);
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0xf];
    }
    var m = try Managed.init(allocator);
    errdefer m.deinit();
    try m.setString(16, hex);
    return m;
}

fn bigToBytesPadded(allocator: Allocator, m: *const Managed, out_len: usize) ![]u8 {
    var hex = try m.toString(allocator, 16, .lower);
    defer allocator.free(hex);
    if (hex.len % 2 == 1) {
        const padded = try std.fmt.allocPrint(allocator, "0{s}", .{hex});
        allocator.free(hex);
        hex = padded;
    }
    const raw_len = hex.len / 2;
    if (raw_len > out_len) return error.Overflow;
    const out = try allocator.alloc(u8, out_len);
    @memset(out, 0);
    _ = try std.fmt.hexToBytes(out[out_len - raw_len ..], hex);
    return out;
}

/// Verify-only RSA modular exponentiation: base^exp mod n, all as
/// big-endian byte strings. Square-and-multiply, no side-channel hardening
/// (verification only, no secret exponent involved).
fn modPow(allocator: Allocator, base_bytes: []const u8, exp_bytes: []const u8, mod_bytes: []const u8) ![]u8 {
    var mod_m = try managedFromBytes(allocator, mod_bytes);
    defer mod_m.deinit();
    var base_m = try managedFromBytes(allocator, base_bytes);
    defer base_m.deinit();
    var exp_m = try managedFromBytes(allocator, exp_bytes);
    defer exp_m.deinit();

    {
        var q = try Managed.init(allocator);
        defer q.deinit();
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        try q.divTrunc(&r, &base_m, &mod_m);
        base_m.deinit();
        base_m = r;
    }

    var result = try Managed.initSet(allocator, 1);
    errdefer result.deinit();

    while (!exp_m.eqlZero()) {
        if (exp_m.isOdd()) {
            var tmp = try Managed.init(allocator);
            defer tmp.deinit();
            try tmp.mul(&result, &base_m);
            var q = try Managed.init(allocator);
            defer q.deinit();
            var r = try Managed.init(allocator);
            errdefer r.deinit();
            try q.divTrunc(&r, &tmp, &mod_m);
            result.deinit();
            result = r;
        }
        {
            var tmp2 = try Managed.init(allocator);
            defer tmp2.deinit();
            try tmp2.mul(&base_m, &base_m);
            var q2 = try Managed.init(allocator);
            defer q2.deinit();
            var r2 = try Managed.init(allocator);
            errdefer r2.deinit();
            try q2.divTrunc(&r2, &tmp2, &mod_m);
            base_m.deinit();
            base_m = r2;
        }
        {
            var new_exp = try Managed.init(allocator);
            errdefer new_exp.deinit();
            try new_exp.shiftRight(&exp_m, 1);
            exp_m.deinit();
            exp_m = new_exp;
        }
    }

    defer result.deinit();
    return bigToBytesPadded(allocator, &result, mod_bytes.len);
}

const rsa_sha256_digest_info_prefix = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

fn verifyRs256(allocator: Allocator, msg: []const u8, sig_bytes: []const u8, jwk: Jwk) !void {
    if (jwk != .rsa) return error.UnsupportedAlg;
    const rsa = jwk.rsa;

    const em = try modPow(allocator, sig_bytes, rsa.e, rsa.n);
    defer allocator.free(em);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &hash, .{});

    const t_len = rsa_sha256_digest_info_prefix.len + hash.len;
    if (em.len < t_len + 11) return error.InvalidKey;
    const ps_len = em.len - t_len - 3;

    if (em[0] != 0x00 or em[1] != 0x01) return error.InvalidSignature;
    for (em[2 .. 2 + ps_len]) |b| {
        if (b != 0xFF) return error.InvalidSignature;
    }
    if (em[2 + ps_len] != 0x00) return error.InvalidSignature;
    const rest = em[2 + ps_len + 1 ..];
    if (!std.mem.eql(u8, rest[0..rsa_sha256_digest_info_prefix.len], &rsa_sha256_digest_info_prefix)) return error.InvalidSignature;
    if (!std.mem.eql(u8, rest[rsa_sha256_digest_info_prefix.len..], &hash)) return error.InvalidSignature;
}

/// Split, decode, verify signature, and validate claims for a compact JWT
/// (`header.payload.signature`, all base64url). `allocator` is expected to
/// be an arena (or otherwise long-lived relative to the caller) — returned
/// `Claims` strings are subslices of the decoded payload JSON.
pub fn validateJwt(allocator: Allocator, oidc: *OidcConfig, token: []const u8) !Claims {
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return error.Malformed;
    const header_b64 = token[0..dot1];
    const payload_b64 = token[dot1 + 1 .. dot2];
    const sig_b64 = token[dot2 + 1 ..];
    const signing_input = token[0..dot2];

    const header_json = b64UrlDecodeAlloc(allocator, header_b64) catch return error.Malformed;
    const payload_json = b64UrlDecodeAlloc(allocator, payload_b64) catch return error.Malformed;
    const sig_bytes = b64UrlDecodeAlloc(allocator, sig_b64) catch return error.Malformed;

    const header_doc = std.json.parseFromSliceLeaky(std.json.Value, allocator, header_json, .{}) catch return error.Malformed;
    const payload_doc = std.json.parseFromSliceLeaky(std.json.Value, allocator, payload_json, .{}) catch return error.Malformed;

    const alg = getStr(header_doc, "alg") orelse return error.UnsupportedAlg;
    const kid = getStr(header_doc, "kid") orelse "";

    const jwk = getKey(oidc, allocator, kid) catch return error.UnknownKid;

    if (std.mem.eql(u8, alg, "ES256")) {
        try verifyEs256(signing_input, sig_bytes, jwk);
    } else if (std.mem.eql(u8, alg, "RS256")) {
        try verifyRs256(allocator, signing_input, sig_bytes, jwk);
    } else {
        return error.UnsupportedAlg;
    }

    const iss = getStr(payload_doc, "iss") orelse return error.IssuerMismatch;
    if (!std.mem.eql(u8, iss, oidc.issuer)) return error.IssuerMismatch;

    if (oidc.audience.len > 0) {
        if (!audienceMatches(payload_doc, oidc.audience)) return error.AudienceMismatch;
    }

    const exp = getInt(payload_doc, "exp") orelse return error.TokenExpired;
    if (exp <= std.time.timestamp()) return error.TokenExpired;

    const sub = getStr(payload_doc, "sub") orelse return error.MissingSub;
    const policy_name = getStr(payload_doc, "policy");

    return .{ .sub = sub, .policy_name = policy_name };
}

fn loadNamedPolicy(allocator: Allocator, data_dir: std.fs.Dir, name: []const u8) ?[]const u8 {
    if (name.len == 0) return null;
    for (name) |c| {
        if (c == '/' or c == '\\' or c == 0) return null;
    }
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return null;

    var policies_dir = data_dir.openDir(".simpaniz-iam/policies", .{}) catch return null;
    defer policies_dir.close();
    const filename = std.fmt.allocPrint(allocator, "{s}.json", .{name}) catch return null;
    return policies_dir.readFileAlloc(allocator, filename, 1024 * 1024) catch null;
}

/// Unsigned endpoint: identity comes from a validated OIDC JWT, not SigV4.
/// `query` is the raw (undecoded) request query string.
/// ponytail: query-param API only; form-body POST is not parsed yet.
pub fn handleAssumeRoleWithWebIdentity(allocator: Allocator, store: *StsStore, oidc: *OidcConfig, query: []const u8, request_id: []const u8) http.Response {
    if (!oidc.enabled) return errorResponse(allocator, 400, "InvalidIdentityToken", "OIDC is not configured on this server.", request_id);

    const token_raw = qp(query, "WebIdentityToken") orelse return errorResponse(allocator, 400, "InvalidIdentityToken", "Missing WebIdentityToken parameter.", request_id);
    const token = util.urlDecode(allocator, token_raw) catch return errorResponse(allocator, 400, "InvalidIdentityToken", "Malformed WebIdentityToken.", request_id);

    const claims = validateJwt(allocator, oidc, token) catch |e| {
        return switch (e) {
            error.TokenExpired => errorResponse(allocator, 400, "ExpiredToken", "The web identity token has expired.", request_id),
            else => errorResponse(allocator, 400, "InvalidIdentityToken", "The web identity token is invalid.", request_id),
        };
    };

    const duration_s: u32 = if (qp(query, "DurationSeconds")) |d| (std.fmt.parseInt(u32, d, 10) catch 0) else 0;

    var session_policy: ?[]const u8 = null;
    if (qp(query, "Policy")) |pol_enc| {
        session_policy = util.urlDecode(allocator, pol_enc) catch null;
    } else if (claims.policy_name) |pn| {
        session_policy = loadNamedPolicy(allocator, oidc.data_dir, pn);
    } else if (oidc.default_policy_name.len > 0) {
        session_policy = loadNamedPolicy(allocator, oidc.data_dir, oidc.default_policy_name);
    }
    // ponytail: no policy resolved → creds issued with no session policy;
    // iam.authorize's default-deny for non-root then blocks everything
    // until an explicit user/bucket policy grants access.

    const cred = store.issue(claims.sub, false, session_policy, duration_s) catch
        return errorResponse(allocator, 500, "InternalError", "Failed to issue temporary credentials.", request_id);

    return buildAssumeRoleXml(allocator, "AssumeRoleWithWebIdentityResponse", "AssumeRoleWithWebIdentityResult", cred, request_id);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "StsStore issue/lookup roundtrip" {
    const a = std.testing.allocator;
    var store = StsStore.init(a);
    defer store.deinit();

    const cred = try store.issue("AKIAROOT", true, null, 3600);
    const ak = cred.access_key;
    const token = try a.dupe(u8, cred.session_token);
    defer a.free(token);

    const found = store.lookup(&ak, token) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("AKIAROOT", found.base_principal);
    try std.testing.expect(found.is_root_base);
}

test "StsStore lookup rejects wrong token" {
    const a = std.testing.allocator;
    var store = StsStore.init(a);
    defer store.deinit();

    const cred = try store.issue("AKIAUSER1", false, null, 3600);
    const ak = cred.access_key;
    try std.testing.expect(store.lookup(&ak, "not-the-right-token-at-all-0000000000000000") == null);
}

test "StsStore lookup rejects expired cred" {
    const a = std.testing.allocator;
    var store = StsStore.init(a);
    defer store.deinit();

    // duration_s below the 900s floor still clamps, so force expiry by
    // reaching in and rewriting expires_unix directly (test-only).
    const cred_const = try store.issue("AKIAUSER1", false, null, 900);
    const ak = cred_const.access_key;
    const token = try a.dupe(u8, cred_const.session_token);
    defer a.free(token);

    const mutable: *TempCred = @constCast(cred_const);
    mutable.expires_unix = std.time.timestamp() - 10;

    try std.testing.expect(store.lookup(&ak, token) == null);
}

test "StsStore clamps duration" {
    const a = std.testing.allocator;
    var store = StsStore.init(a);
    defer store.deinit();

    const now = std.time.timestamp();
    const too_short = try store.issue("root", true, null, 10);
    try std.testing.expect(too_short.expires_unix - now <= 900 + 2 and too_short.expires_unix - now >= 900 - 2);

    const too_long = try store.issue("root", true, null, 999999);
    try std.testing.expect(too_long.expires_unix - now <= 43200 + 2);
}

test "handleAssumeRole returns issued values in XML" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const principal = iam.Principal{ .access_key = "AKIAROOT", .is_root = true };
    const resp = handleAssumeRole(a, &store, principal, "DurationSeconds=1800", "req-1");
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    const body = resp.body.bytes;
    try std.testing.expect(std.mem.indexOf(u8, body, "AssumeRoleResponse") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<AccessKeyId>STS") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<SessionToken>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "req-1") != null);
}

test "handleAssumeRole denies anonymous caller" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const resp = handleAssumeRole(a, &store, null, "", "req-2");
    try std.testing.expectEqual(@as(u16, 403), resp.status);
}

fn b64UrlEncodeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(input.len));
    _ = encoder.encode(out, input);
    return out;
}

fn buildTestJwtEs256(allocator: Allocator, key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair, header_json: []const u8, payload_json: []const u8) ![]u8 {
    const header_b64 = try b64UrlEncodeAlloc(allocator, header_json);
    const payload_b64 = try b64UrlEncodeAlloc(allocator, payload_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    const sig = try key_pair.sign(signing_input, null);
    const sig_bytes = sig.toBytes();
    const sig_b64 = try b64UrlEncodeAlloc(allocator, &sig_bytes);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
}

test "JWT ES256 end-to-end via injected JWK" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
    const sec1 = key_pair.public_key.toUncompressedSec1();

    var oidc = OidcConfig{
        .allocator = std.testing.allocator,
        .enabled = true,
        .issuer = "https://issuer.example",
        .audience = "simpaniz",
        .keys = std.StringHashMap(Jwk).init(std.testing.allocator),
        .data_dir = std.fs.cwd(),
    };
    // Not oidc.deinit(): issuer/audience here are string literals, not
    // heap-owned by std.testing.allocator (unlike OidcConfig.load()'s env
    // vars) — only the keys map (and its heap-duped Jwk contents) needs
    // freeing in these tests.
    defer {
        var kit = oidc.keys.iterator();
        while (kit.next()) |entry| std.testing.allocator.free(entry.key_ptr.*);
        oidc.keys.deinit();
    }

    var ec: Jwk = .{ .ec_p256 = undefined };
    @memcpy(&ec.ec_p256.x, sec1[1..33]);
    @memcpy(&ec.ec_p256.y, sec1[33..65]);
    try oidc.keys.put(try std.testing.allocator.dupe(u8, "test-kid"), ec);

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    const header_json = "{\"alg\":\"ES256\",\"kid\":\"test-kid\"}";
    const payload_json = try std.fmt.allocPrint(a, "{{\"iss\":\"https://issuer.example\",\"aud\":\"simpaniz\",\"exp\":{d},\"sub\":\"user-123\"}}", .{now + 3600});

    const token = try buildTestJwtEs256(a, key_pair, header_json, payload_json);
    const query = try std.fmt.allocPrint(a, "Action=AssumeRoleWithWebIdentity&WebIdentityToken={s}", .{token});

    const resp = handleAssumeRoleWithWebIdentity(a, &store, &oidc, query, "req-oidc-1");
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "AssumeRoleWithWebIdentityResponse") != null);
}

test "JWT ES256 tampered payload rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
    const sec1 = key_pair.public_key.toUncompressedSec1();

    var oidc = OidcConfig{
        .allocator = std.testing.allocator,
        .enabled = true,
        .issuer = "https://issuer.example",
        .keys = std.StringHashMap(Jwk).init(std.testing.allocator),
        .data_dir = std.fs.cwd(),
    };
    // Not oidc.deinit(): issuer/audience here are string literals, not
    // heap-owned by std.testing.allocator (unlike OidcConfig.load()'s env
    // vars) — only the keys map (and its heap-duped Jwk contents) needs
    // freeing in these tests.
    defer {
        var kit = oidc.keys.iterator();
        while (kit.next()) |entry| std.testing.allocator.free(entry.key_ptr.*);
        oidc.keys.deinit();
    }

    var ec: Jwk = .{ .ec_p256 = undefined };
    @memcpy(&ec.ec_p256.x, sec1[1..33]);
    @memcpy(&ec.ec_p256.y, sec1[33..65]);
    try oidc.keys.put(try std.testing.allocator.dupe(u8, "test-kid"), ec);

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    const header_json = "{\"alg\":\"ES256\",\"kid\":\"test-kid\"}";
    const payload_json = try std.fmt.allocPrint(a, "{{\"iss\":\"https://issuer.example\",\"exp\":{d},\"sub\":\"user-123\"}}", .{now + 3600});
    const token = try buildTestJwtEs256(a, key_pair, header_json, payload_json);

    // Flip a byte in the payload segment (index just past the first dot).
    const tampered = try a.dupe(u8, token);
    const dot = std.mem.indexOfScalar(u8, tampered, '.').?;
    tampered[dot + 1] = if (tampered[dot + 1] == 'A') 'B' else 'A';

    const query = try std.fmt.allocPrint(a, "WebIdentityToken={s}", .{tampered});
    const resp = handleAssumeRoleWithWebIdentity(a, &store, &oidc, query, "req-oidc-2");
    try std.testing.expectEqual(@as(u16, 400), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "InvalidIdentityToken") != null);
}

test "JWT ES256 expired token rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
    const sec1 = key_pair.public_key.toUncompressedSec1();

    var oidc = OidcConfig{
        .allocator = std.testing.allocator,
        .enabled = true,
        .issuer = "https://issuer.example",
        .keys = std.StringHashMap(Jwk).init(std.testing.allocator),
        .data_dir = std.fs.cwd(),
    };
    // Not oidc.deinit(): issuer/audience here are string literals, not
    // heap-owned by std.testing.allocator (unlike OidcConfig.load()'s env
    // vars) — only the keys map (and its heap-duped Jwk contents) needs
    // freeing in these tests.
    defer {
        var kit = oidc.keys.iterator();
        while (kit.next()) |entry| std.testing.allocator.free(entry.key_ptr.*);
        oidc.keys.deinit();
    }

    var ec: Jwk = .{ .ec_p256 = undefined };
    @memcpy(&ec.ec_p256.x, sec1[1..33]);
    @memcpy(&ec.ec_p256.y, sec1[33..65]);
    try oidc.keys.put(try std.testing.allocator.dupe(u8, "test-kid"), ec);

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    const header_json = "{\"alg\":\"ES256\",\"kid\":\"test-kid\"}";
    const payload_json = try std.fmt.allocPrint(a, "{{\"iss\":\"https://issuer.example\",\"exp\":{d},\"sub\":\"user-123\"}}", .{now - 3600});
    const token = try buildTestJwtEs256(a, key_pair, header_json, payload_json);

    const query = try std.fmt.allocPrint(a, "WebIdentityToken={s}", .{token});
    const resp = handleAssumeRoleWithWebIdentity(a, &store, &oidc, query, "req-oidc-3");
    try std.testing.expectEqual(@as(u16, 400), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "ExpiredToken") != null);
}

test "JWT ES256 wrong issuer rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
    const sec1 = key_pair.public_key.toUncompressedSec1();

    var oidc = OidcConfig{
        .allocator = std.testing.allocator,
        .enabled = true,
        .issuer = "https://issuer.example",
        .keys = std.StringHashMap(Jwk).init(std.testing.allocator),
        .data_dir = std.fs.cwd(),
    };
    // Not oidc.deinit(): issuer/audience here are string literals, not
    // heap-owned by std.testing.allocator (unlike OidcConfig.load()'s env
    // vars) — only the keys map (and its heap-duped Jwk contents) needs
    // freeing in these tests.
    defer {
        var kit = oidc.keys.iterator();
        while (kit.next()) |entry| std.testing.allocator.free(entry.key_ptr.*);
        oidc.keys.deinit();
    }

    var ec: Jwk = .{ .ec_p256 = undefined };
    @memcpy(&ec.ec_p256.x, sec1[1..33]);
    @memcpy(&ec.ec_p256.y, sec1[33..65]);
    try oidc.keys.put(try std.testing.allocator.dupe(u8, "test-kid"), ec);

    var store = StsStore.init(std.testing.allocator);
    defer store.deinit();

    const now = std.time.timestamp();
    const header_json = "{\"alg\":\"ES256\",\"kid\":\"test-kid\"}";
    const payload_json = try std.fmt.allocPrint(a, "{{\"iss\":\"https://not-the-issuer.example\",\"exp\":{d},\"sub\":\"user-123\"}}", .{now + 3600});
    const token = try buildTestJwtEs256(a, key_pair, header_json, payload_json);

    const query = try std.fmt.allocPrint(a, "WebIdentityToken={s}", .{token});
    const resp = handleAssumeRoleWithWebIdentity(a, &store, &oidc, query, "req-oidc-4");
    try std.testing.expectEqual(@as(u16, 400), resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body.bytes, "InvalidIdentityToken") != null);
}

test "modPow textbook RSA vector (n=3233, e=17)" {
    const a = std.testing.allocator;
    // 65^17 mod 3233 = 2790 (classic RSA teaching example: p=61, q=53).
    const base = [_]u8{65};
    const exp = [_]u8{17};
    const modn = [_]u8{ 0x0c, 0xa1 }; // 3233
    const out = try modPow(a, &base, &exp, &modn);
    defer a.free(out);
    try std.testing.expectEqual(@as(usize, 2), out.len);
    const value = (@as(u16, out[0]) << 8) | out[1];
    try std.testing.expectEqual(@as(u16, 2790), value);

    // tested via ES256 path + modexp unit above; a full RS256 JWT vector
    // (needs an externally-signed fixture — no RSA signer in std) is
    // pending.
}
