//! IAM user store + AWS-style policy evaluation engine.
//!
//! Provides a lightweight, file-backed multi-user credential store
//! (`<data_dir>/.simpaniz-iam/users.json`) plus an S3 bucket/user policy
//! evaluator modeled on AWS IAM policy semantics: Effect / Action /
//! Resource / Principal / Condition, with explicit-deny-wins combination.
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");

// ── Types ────────────────────────────────────────────────────────────────────

pub const Principal = struct {
    access_key: []const u8,
    is_root: bool,
};

pub const Decision = enum { allow, deny, none };

pub const User = struct {
    access_key: []const u8,
    secret_key: []const u8,
    enabled: bool,
    /// Parsed inline policy document, owned by the Store's arena.
    policy: ?std.json.Value,
};

pub const Store = struct {
    arena: std.heap.ArenaAllocator,
    users: []User,

    pub fn deinit(self: *Store) void {
        self.arena.deinit();
    }

    pub fn findUser(self: *const Store, access_key: []const u8) ?*const User {
        for (self.users, 0..) |u, i| {
            if (!u.enabled) continue;
            if (std.mem.eql(u8, u.access_key, access_key)) return &self.users[i];
        }
        return null;
    }
};

const IAM_DIR = ".simpaniz-iam";
const USERS_FILE = "users.json";
const MAX_USERS_FILE_BYTES = 16 * 1024 * 1024;

/// Load the IAM user store from `<data_dir>/.simpaniz-iam/users.json`.
/// Missing directory/file is not an error (empty store). Malformed JSON
/// logs an error and also yields an empty store so a bad file never blocks
/// startup or takes down existing root-credential auth.
pub fn load(gpa: Allocator, data_dir: std.fs.Dir) Store {
    var arena = std.heap.ArenaAllocator.init(gpa);
    const a = arena.allocator();
    const empty: Store = .{ .arena = arena, .users = &.{} };

    var iam_dir = data_dir.openDir(IAM_DIR, .{}) catch return empty;
    defer iam_dir.close();

    const bytes = iam_dir.readFileAlloc(a, USERS_FILE, MAX_USERS_FILE_BYTES) catch |e| {
        if (e != error.FileNotFound) std.log.err("iam: failed to read {s}: {}", .{ USERS_FILE, e });
        return empty;
    };

    const doc = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch |e| {
        std.log.err("iam: malformed {s}: {}", .{ USERS_FILE, e });
        return empty;
    };
    if (doc != .object) {
        std.log.err("iam: {s} root is not a JSON object", .{USERS_FILE});
        return empty;
    }
    const users_val = doc.object.get("users") orelse return empty;
    if (users_val != .array) {
        std.log.err("iam: {s} \"users\" field is not an array", .{USERS_FILE});
        return empty;
    }

    var list = std.ArrayList(User){};
    for (users_val.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const ak_v = obj.get("access_key") orelse continue;
        const sk_v = obj.get("secret_key") orelse continue;
        if (ak_v != .string or sk_v != .string) continue;
        const enabled = if (obj.get("enabled")) |ev| (if (ev == .bool) ev.bool else true) else true;
        list.append(a, .{
            .access_key = ak_v.string,
            .secret_key = sk_v.string,
            .enabled = enabled,
            .policy = obj.get("policy"),
        }) catch continue;
    }

    const slice = list.toOwnedSlice(a) catch list.items;
    return .{ .arena = arena, .users = slice };
}

// ── Action mapping ───────────────────────────────────────────────────────────

fn qp(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
            if (std.mem.eql(u8, param[0..eq], key)) return param[eq + 1 ..];
        }
    }
    return null;
}

fn hasFlag(query: []const u8, key: []const u8) bool {
    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |param| {
        const name = if (std.mem.indexOfScalar(u8, param, '=')) |eq| param[0..eq] else param;
        if (std.mem.eql(u8, name, key)) return true;
    }
    return false;
}

/// Map an S3 request (method + bucket + key + query) to the IAM action
/// string it requires. Mirrors `router.zig`'s routing order exactly so the
/// mapped action always matches the handler that will actually run.
pub fn mapAction(method: http.Method, bucket: []const u8, key: []const u8, query: []const u8) []const u8 {
    if (bucket.len == 0) return "s3:ListAllMyBuckets";

    // ── Bucket-level (key empty) ─────────────────────────────────────────────
    if (key.len == 0) {
        if (method == .POST and hasFlag(query, "delete")) return "s3:DeleteObject";
        if (hasFlag(query, "policy")) {
            return switch (method) {
                .PUT => "s3:PutBucketPolicy",
                .GET => "s3:GetBucketPolicy",
                .DELETE => "s3:DeleteBucketPolicy",
                else => "s3:*",
            };
        }
        if (hasFlag(query, "lifecycle")) {
            return switch (method) {
                .PUT => "s3:PutLifecycleConfiguration",
                .GET => "s3:GetLifecycleConfiguration",
                .DELETE => "s3:PutLifecycleConfiguration",
                else => "s3:*",
            };
        }
        if (hasFlag(query, "versioning")) {
            return switch (method) {
                .PUT => "s3:PutBucketVersioning",
                .GET => "s3:GetBucketVersioning",
                else => "s3:*",
            };
        }
        if (hasFlag(query, "object-lock")) {
            return switch (method) {
                .PUT => "s3:PutBucketObjectLockConfiguration",
                .GET => "s3:GetBucketObjectLockConfiguration",
                else => "s3:*",
            };
        }
        if (hasFlag(query, "notification")) {
            return switch (method) {
                .PUT => "s3:PutBucketNotification",
                .GET => "s3:GetBucketNotification",
                else => "s3:*",
            };
        }
        if (hasFlag(query, "encryption")) {
            return switch (method) {
                .PUT => "s3:PutEncryptionConfiguration",
                .GET => "s3:GetEncryptionConfiguration",
                .DELETE => "s3:PutEncryptionConfiguration",
                else => "s3:*",
            };
        }
        if (method == .GET and hasFlag(query, "versions")) return "s3:ListBucketVersions";
        if (method == .GET and hasFlag(query, "uploads")) return "s3:ListBucketMultipartUploads";
        return switch (method) {
            .PUT => "s3:CreateBucket",
            .DELETE => "s3:DeleteBucket",
            .HEAD => "s3:ListBucket",
            .GET => "s3:ListBucket",
            else => "s3:*",
        };
    }

    // ── Object-level ──────────────────────────────────────────────────────────
    if (method == .POST and hasFlag(query, "uploads")) return "s3:PutObject";
    if (qp(query, "uploadId") != null) {
        return switch (method) {
            .PUT => "s3:PutObject",
            .POST => "s3:PutObject",
            .DELETE => "s3:AbortMultipartUpload",
            .GET => "s3:ListMultipartUploadParts",
            else => "s3:*",
        };
    }
    if (hasFlag(query, "tagging")) {
        return switch (method) {
            .PUT => "s3:PutObjectTagging",
            .GET => "s3:GetObjectTagging",
            .DELETE => "s3:DeleteObjectTagging",
            else => "s3:*",
        };
    }
    if (hasFlag(query, "retention")) {
        return switch (method) {
            .PUT => "s3:PutObjectRetention",
            .GET => "s3:GetObjectRetention",
            else => "s3:*",
        };
    }
    if (hasFlag(query, "legal-hold")) {
        return switch (method) {
            .PUT => "s3:PutObjectLegalHold",
            .GET => "s3:GetObjectLegalHold",
            else => "s3:*",
        };
    }
    return switch (method) {
        .PUT => "s3:PutObject",
        .GET => "s3:GetObject",
        .HEAD => "s3:GetObject",
        .DELETE => "s3:DeleteObject",
        else => "s3:*",
    };
}

// ── Policy evaluation ────────────────────────────────────────────────────────

/// Iterative two-pointer wildcard match. `*` matches any run of characters
/// (including empty), `?` matches exactly one character. No recursion, so
/// pathological patterns can't blow the stack.
fn wildMatch(pattern: []const u8, s: []const u8) bool {
    var p_i: usize = 0;
    var s_i: usize = 0;
    var star_p: ?usize = null;
    var star_s: usize = 0;

    while (s_i < s.len) {
        if (p_i < pattern.len and (pattern[p_i] == '?' or pattern[p_i] == s[s_i])) {
            p_i += 1;
            s_i += 1;
        } else if (p_i < pattern.len and pattern[p_i] == '*') {
            star_p = p_i;
            star_s = s_i;
            p_i += 1;
        } else if (star_p) |sp| {
            p_i = sp + 1;
            star_s += 1;
            s_i = star_s;
        } else {
            return false;
        }
    }
    while (p_i < pattern.len and pattern[p_i] == '*') p_i += 1;
    return p_i == pattern.len;
}

fn valueMatchesAny(v: std.json.Value, s: []const u8) bool {
    return switch (v) {
        .string => |str| wildMatch(str, s),
        .array => |arr| blk: {
            for (arr.items) |item| {
                if (item == .string and wildMatch(item.string, s)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

fn principalEntryMatches(entry: []const u8, ak: []const u8) bool {
    if (std.mem.eql(u8, entry, ak)) return true;
    // Accept ARN form: arn:aws:iam::<account>:user/<access_key>.
    var buf: [256]u8 = undefined;
    const suffix = std.fmt.bufPrint(&buf, ":user/{s}", .{ak}) catch return false;
    return std.mem.endsWith(u8, entry, suffix);
}

fn principalMatches(v: std.json.Value, principal_ak: ?[]const u8) bool {
    return switch (v) {
        .string => |str| matchesOnePrincipal(str, principal_ak),
        .object => |obj| blk: {
            const aws_v = obj.get("AWS") orelse break :blk false;
            break :blk switch (aws_v) {
                .string => |str| matchesOnePrincipal(str, principal_ak),
                .array => |arr| inner: {
                    for (arr.items) |item| {
                        if (item == .string and matchesOnePrincipal(item.string, principal_ak)) break :inner true;
                    }
                    break :inner false;
                },
                else => false,
            };
        },
        else => false,
    };
}

fn matchesOnePrincipal(entry: []const u8, principal_ak: ?[]const u8) bool {
    if (std.mem.eql(u8, entry, "*")) return true;
    const ak = principal_ak orelse return false;
    return principalEntryMatches(entry, ak);
}

/// Evaluate a single policy document (bucket policy or user inline policy)
/// against one action/resource. `require_principal` selects bucket-policy
/// semantics (Principal element is mandatory and checked) vs. user inline
/// policy semantics (no Principal element — it's implicitly the user).
pub fn evaluatePolicy(
    doc: std.json.Value,
    principal_ak: ?[]const u8,
    action: []const u8,
    bucket: []const u8,
    key: []const u8,
    require_principal: bool,
) Decision {
    if (doc != .object) return .none;
    const stmt_val = doc.object.get("Statement") orelse return .none;

    var single_buf: [1]std.json.Value = undefined;
    const statements: []const std.json.Value = switch (stmt_val) {
        .array => |arr| arr.items,
        .object => blk: {
            single_buf[0] = stmt_val;
            break :blk single_buf[0..1];
        },
        else => return .none,
    };

    var res_buf: [1200]u8 = undefined;
    const resource = (if (key.len == 0)
        std.fmt.bufPrint(&res_buf, "arn:aws:s3:::{s}", .{bucket})
    else
        std.fmt.bufPrint(&res_buf, "arn:aws:s3:::{s}/{s}", .{ bucket, key })) catch return .none;

    var saw_allow = false;
    var saw_deny = false;

    for (statements) |st| {
        if (st != .object) continue;
        const sobj = st.object;

        const effect_v = sobj.get("Effect") orelse continue;
        if (effect_v != .string) continue;
        const is_allow = std.mem.eql(u8, effect_v.string, "Allow");
        const is_deny = std.mem.eql(u8, effect_v.string, "Deny");
        if (!is_allow and !is_deny) continue;

        // A Condition element means the grant is conditional on things we
        // don't evaluate (IP ranges, time windows, etc). For Allow we can't
        // safely assume the condition holds, so the statement grants
        // nothing (fail open toward denial-by-omission). For Deny we
        // *do* apply it regardless — erring toward blocking access is the
        // safe failure mode (fail closed).
        const has_condition = sobj.get("Condition") != null;
        if (has_condition and is_allow) continue;

        if (require_principal) {
            const principal_v = sobj.get("Principal") orelse continue;
            if (!principalMatches(principal_v, principal_ak)) continue;
        }

        const action_v = sobj.get("Action") orelse continue;
        if (!valueMatchesAny(action_v, action)) continue;

        const resource_v = sobj.get("Resource") orelse continue;
        if (!valueMatchesAny(resource_v, resource)) continue;

        if (is_deny) saw_deny = true else saw_allow = true;
    }

    if (saw_deny) return .deny;
    if (saw_allow) return .allow;
    return .none;
}

/// Decide whether `principal` may perform `action` on `bucket`/`key`.
/// Root always passes (bypasses policy entirely, MinIO-style). Otherwise
/// combines the principal's own inline policy (if any) with the bucket
/// policy (if any); an explicit Deny from either source wins. With no
/// explicit decision: authenticated non-root users default-deny (must be
/// granted), anonymous requests (principal == null, auth not required)
/// default-allow to preserve pre-IAM behavior.
pub fn authorize(
    store: *const Store,
    bucket_policy_json: ?[]const u8,
    principal: ?Principal,
    action: []const u8,
    bucket: []const u8,
    key: []const u8,
    scratch: Allocator,
) bool {
    if (principal) |p| {
        if (p.is_root) return true;
    }

    var saw_allow = false;
    var saw_deny = false;

    if (principal) |p| {
        if (store.findUser(p.access_key)) |user| {
            if (user.policy) |pol| {
                switch (evaluatePolicy(pol, p.access_key, action, bucket, key, false)) {
                    .allow => saw_allow = true,
                    .deny => saw_deny = true,
                    .none => {},
                }
            }
        }
    }

    if (bucket_policy_json) |json| {
        if (std.json.parseFromSliceLeaky(std.json.Value, scratch, json, .{})) |doc| {
            const pak: ?[]const u8 = if (principal) |p| p.access_key else null;
            switch (evaluatePolicy(doc, pak, action, bucket, key, true)) {
                .allow => saw_allow = true,
                .deny => saw_deny = true,
                .none => {},
            }
        } else |e| {
            std.log.warn("iam: malformed bucket policy for {s}: {}", .{ bucket, e });
        }
    }

    if (saw_deny) return false;
    if (saw_allow) return true;
    return principal == null;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "wildMatch star matches everything" {
    try std.testing.expect(wildMatch("*", "anything"));
    try std.testing.expect(wildMatch("*", ""));
}

test "wildMatch prefix star" {
    try std.testing.expect(wildMatch("s3:Get*", "s3:GetObject"));
}

test "wildMatch question mark" {
    try std.testing.expect(wildMatch("s3:Get?bject", "s3:GetObject"));
}

test "wildMatch literal mismatch" {
    try std.testing.expect(!wildMatch("s3:PutObject", "s3:GetObject"));
}

test "wildMatch bucket wildcard does not match bare bucket arn" {
    try std.testing.expect(!wildMatch("arn:aws:s3:::b/*", "arn:aws:s3:::b"));
}

test "wildMatch bucket wildcard matches nested key" {
    try std.testing.expect(wildMatch("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/y"));
}

test "Store.load reads users.json" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(IAM_DIR);
    var iam_dir = try tmp.dir.openDir(IAM_DIR, .{});
    defer iam_dir.close();
    const json =
        \\{
        \\  "users": [
        \\    {
        \\      "access_key": "AKIAUSER1",
        \\      "secret_key": "secret1",
        \\      "enabled": true,
        \\      "policy": { "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": ["s3:GetObject","s3:ListBucket"], "Resource": "arn:aws:s3:::*" } ] }
        \\    }
        \\  ]
        \\}
    ;
    try iam_dir.writeFile(.{ .sub_path = USERS_FILE, .data = json });

    var store = load(std.testing.allocator, tmp.dir);
    defer store.deinit();

    try std.testing.expectEqual(@as(usize, 1), store.users.len);
    const u = store.findUser("AKIAUSER1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("secret1", u.secret_key);
}

test "Store.load missing file returns empty store" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = load(std.testing.allocator, tmp.dir);
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.users.len);
    try std.testing.expect(store.findUser("nope") == null);
}

test "evaluatePolicy deny wins over allow" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"Statement":[
        \\  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},
        \\  {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
        \\]}
    ;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    try std.testing.expectEqual(Decision.deny, evaluatePolicy(doc, null, "s3:GetObject", "b", "x", true));
}

test "evaluatePolicy allow grants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
    ;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    try std.testing.expectEqual(Decision.allow, evaluatePolicy(doc, null, "s3:GetObject", "b", "x", true));
}

test "evaluatePolicy Principal wildcard matches anonymous" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
    ;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    try std.testing.expectEqual(Decision.allow, evaluatePolicy(doc, null, "s3:GetObject", "b", "x", true));
}

test "evaluatePolicy Allow with Condition is skipped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":"1.2.3.4/32"}}}]}
    ;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    try std.testing.expectEqual(Decision.none, evaluatePolicy(doc, null, "s3:GetObject", "b", "x", true));
}

test "evaluatePolicy Deny with Condition still applies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const json =
        \\{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":"1.2.3.4/32"}}}]}
    ;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    try std.testing.expectEqual(Decision.deny, evaluatePolicy(doc, null, "s3:GetObject", "b", "x", true));
}

test "authorize root always allowed" {
    var scratch = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer scratch.deinit();
    var store = Store{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator), .users = &.{} };
    defer store.deinit();
    const principal = Principal{ .access_key = "root", .is_root = true };
    try std.testing.expect(authorize(&store, null, principal, "s3:PutObject", "b", "k", scratch.allocator()));
}

test "authorize user with read-only policy" {
    var store_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const sa = store_arena.allocator();
    const policy_json =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}]}
    ;
    const pol = try std.json.parseFromSliceLeaky(std.json.Value, sa, policy_json, .{});
    var users = [_]User{.{ .access_key = "AKIAUSER1", .secret_key = "s1", .enabled = true, .policy = pol }};
    var store = Store{ .arena = store_arena, .users = &users };
    defer store.deinit();

    var scratch = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer scratch.deinit();

    const principal = Principal{ .access_key = "AKIAUSER1", .is_root = false };
    try std.testing.expect(authorize(&store, null, principal, "s3:GetObject", "b", "x", scratch.allocator()));
    try std.testing.expect(!authorize(&store, null, principal, "s3:PutObject", "b", "x", scratch.allocator()));
}

test "authorize bucket policy deny blocks non-root even if user policy allows" {
    var store_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const sa = store_arena.allocator();
    const policy_json =
        \\{"Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::b/*"}]}
    ;
    const pol = try std.json.parseFromSliceLeaky(std.json.Value, sa, policy_json, .{});
    var users = [_]User{.{ .access_key = "AKIAUSER1", .secret_key = "s1", .enabled = true, .policy = pol }};
    var store = Store{ .arena = store_arena, .users = &users };
    defer store.deinit();

    var scratch = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer scratch.deinit();

    const bucket_policy =
        \\{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}
    ;
    const principal = Principal{ .access_key = "AKIAUSER1", .is_root = false };
    try std.testing.expect(!authorize(&store, bucket_policy, principal, "s3:PutObject", "b", "x", scratch.allocator()));
}

test "mapAction bucket policy subresource" {
    try std.testing.expectEqualStrings("s3:PutBucketPolicy", mapAction(.PUT, "b", "", "policy"));
}

test "mapAction plain get object" {
    try std.testing.expectEqualStrings("s3:GetObject", mapAction(.GET, "b", "k", ""));
}

test "mapAction bulk delete" {
    try std.testing.expectEqualStrings("s3:DeleteObject", mapAction(.POST, "b", "", "delete"));
}

test "mapAction multipart upload part" {
    try std.testing.expectEqualStrings("s3:PutObject", mapAction(.PUT, "b", "k", "uploadId=x&partNumber=1"));
}

test "mapAction bucket notification subresource" {
    try std.testing.expectEqualStrings("s3:PutBucketNotification", mapAction(.PUT, "b", "", "notification"));
    try std.testing.expectEqualStrings("s3:GetBucketNotification", mapAction(.GET, "b", "", "notification"));
}

test "mapAction bucket encryption subresource" {
    try std.testing.expectEqualStrings("s3:PutEncryptionConfiguration", mapAction(.PUT, "b", "", "encryption"));
    try std.testing.expectEqualStrings("s3:GetEncryptionConfiguration", mapAction(.GET, "b", "", "encryption"));
    try std.testing.expectEqualStrings("s3:PutEncryptionConfiguration", mapAction(.DELETE, "b", "", "encryption"));
}
