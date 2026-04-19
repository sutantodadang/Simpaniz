//! HTTP/1.1 request parser and response writer with streaming bodies,
//! raw header preservation (for SigV4), and pluggable response bodies
//! (in-memory bytes or a file slice for zero-copy GET/Range).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = std.fs.File;

// ── HTTP method ──────────────────────────────────────────────────────────────

pub const Method = enum {
    GET,
    PUT,
    DELETE,
    HEAD,
    POST,
    OPTIONS,

    pub fn parse(s: []const u8) ?Method {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        return null;
    }

    pub fn name(self: Method) []const u8 {
        return @tagName(self);
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// ── Request ──────────────────────────────────────────────────────────────────

pub const Request = struct {
    method: Method,
    /// URL-decoded path (safe for filesystem operations).
    path: []const u8,
    /// Raw, undecoded path as it appeared on the wire (for SigV4 canonical URI).
    raw_path: []const u8,
    /// Raw query string (after '?'), undecoded.
    query: []const u8,
    /// All request headers in receive order. Names lowercased.
    headers: []Header,
    /// Value of Content-Length header, or 0.
    content_length: u64,
    content_type: []const u8,
    /// Reader positioned at the start of the body. Handler may read up to
    /// `content_length` bytes; remaining bytes are drained by the server
    /// after the handler returns.
    body_reader: *Io.Reader,
    /// Handler-tracked bytes consumed from `body_reader`. The server uses
    /// this to know how much to discard for keep-alive correctness.
    body_consumed: usize,
    /// Per-request arena (handler-scoped allocations).
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Request) void {
        self.arena.deinit();
    }

    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Read up to `out.len` bytes of the body. Returns 0 at EOF.
    pub fn readBody(self: *Request, out: []u8) !usize {
        const remaining = self.content_length - self.body_consumed;
        if (remaining == 0) return 0;
        const want = @min(remaining, out.len);
        const got = try self.body_reader.readSliceShort(out[0..want]);
        self.body_consumed += got;
        return got;
    }

    /// Read entire remaining body into a freshly allocated buffer.
    /// Caller must enforce a sensible max via `max_len`.
    pub fn readBodyAlloc(self: *Request, allocator: Allocator, max_len: usize) ![]u8 {
        const remaining = self.content_length - self.body_consumed;
        if (remaining > max_len) return error.RequestTooLarge;
        const buf = try allocator.alloc(u8, @intCast(remaining));
        errdefer allocator.free(buf);
        try self.body_reader.readSliceAll(buf);
        self.body_consumed += buf.len;
        return buf;
    }
};

// ── Response ─────────────────────────────────────────────────────────────────

pub const Body = union(enum) {
    none,
    bytes: []const u8,
    file: FileSlice,
    encrypted_file: EncryptedFile,

    pub const FileSlice = struct {
        file: File,
        offset: u64,
        length: u64,
        /// Whether this Response owns the file handle (server will close it).
        owns_file: bool,
    };

    pub const EncryptedFile = struct {
        file: File,
        /// Plaintext length to emit (Content-Length).
        plaintext_length: u64,
        /// 32-byte data-encryption key (already unwrapped).
        dek: [32]u8,
        owns_file: bool,
    };

    pub fn length(self: Body) u64 {
        return switch (self) {
            .none => 0,
            .bytes => |b| b.len,
            .file => |f| f.length,
            .encrypted_file => |e| e.plaintext_length,
        };
    }
};

pub const Response = struct {
    status: u16 = 200,
    status_text: []const u8 = "OK",
    content_type: []const u8 = "application/xml",
    body: Body = .none,
    /// "Name: Value" header lines (without trailing CRLF).
    extra_headers: []const []const u8 = &.{},
};

// ── Parse request ────────────────────────────────────────────────────────────

pub const ParseError = error{
    MalformedRequest,
    UnsupportedMethod,
    HeaderTooLarge,
    TooManyHeaders,
    ReadFailed,
    OutOfMemory,
    StreamTooLong,
};

pub const ParseLimits = struct {
    max_header_bytes: usize = 16 * 1024,
    max_headers: usize = 64,
};

/// Parse the request line and headers (no body). The returned Request keeps
/// a pointer to `reader` for streaming the body; `reader` must outlive the
/// Request.
pub fn parseRequest(reader: *Io.Reader, allocator: Allocator, limits: ParseLimits) ParseError!Request {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const request_line = reader.takeDelimiterInclusive('\n') catch |e| switch (e) {
        error.StreamTooLong => return error.HeaderTooLarge,
        else => return error.ReadFailed,
    };
    if (request_line.len > limits.max_header_bytes) return error.HeaderTooLarge;

    const trimmed = std.mem.trimRight(u8, request_line, "\r\n");
    if (trimmed.len == 0) return error.MalformedRequest;

    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const method_str = parts.first();
    const raw_uri = parts.next() orelse return error.MalformedRequest;

    const method = Method.parse(method_str) orelse return error.UnsupportedMethod;

    var raw_path: []const u8 = raw_uri;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, raw_uri, '?')) |q| {
        raw_path = raw_uri[0..q];
        query = raw_uri[q + 1 ..];
    }

    const owned_raw_path = a.dupe(u8, raw_path) catch return error.OutOfMemory;
    const owned_query = a.dupe(u8, query) catch return error.OutOfMemory;

    // URL-decode path for handlers.
    const decoded_path = urlDecodeArena(a, owned_raw_path) catch return error.MalformedRequest;

    var headers = std.ArrayList(Header){};
    errdefer headers.deinit(a);

    var content_length: u64 = 0;
    var content_type: []const u8 = "application/octet-stream";

    while (true) {
        const line = reader.takeDelimiterInclusive('\n') catch |e| switch (e) {
            error.StreamTooLong => return error.HeaderTooLarge,
            else => return error.ReadFailed,
        };
        if (line.len > limits.max_header_bytes) return error.HeaderTooLarge;
        const ht = std.mem.trimRight(u8, line, "\r\n");
        if (ht.len == 0) break;
        if (headers.items.len >= limits.max_headers) return error.TooManyHeaders;

        const colon = std.mem.indexOfScalar(u8, ht, ':') orelse return error.MalformedRequest;
        const raw_name = std.mem.trim(u8, ht[0..colon], " ");
        const raw_value = std.mem.trim(u8, ht[colon + 1 ..], " ");

        const name = a.alloc(u8, raw_name.len) catch return error.OutOfMemory;
        for (raw_name, 0..) |c, i| name[i] = std.ascii.toLower(c);
        const value = a.dupe(u8, raw_value) catch return error.OutOfMemory;

        if (std.mem.eql(u8, name, "content-length")) {
            content_length = std.fmt.parseInt(u64, value, 10) catch 0;
        } else if (std.mem.eql(u8, name, "content-type")) {
            content_type = value;
        }
        headers.append(a, .{ .name = name, .value = value }) catch return error.OutOfMemory;
    }

    return .{
        .method = method,
        .path = decoded_path,
        .raw_path = owned_raw_path,
        .query = owned_query,
        .headers = headers.toOwnedSlice(a) catch return error.OutOfMemory,
        .content_length = content_length,
        .content_type = content_type,
        .body_reader = reader,
        .body_consumed = 0,
        .arena = arena,
    };
}

fn urlDecodeArena(a: Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(a);
    try out.ensureTotalCapacity(a, input.len);
    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '%') {
            if (i + 2 >= input.len) return error.InvalidPercentEncoding;
            const hi = hexNibble(input[i + 1]) orelse return error.InvalidPercentEncoding;
            const lo = hexNibble(input[i + 2]) orelse return error.InvalidPercentEncoding;
            try out.append(a, (hi << 4) | lo);
            i += 3;
        } else {
            try out.append(a, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(a);
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ── Write response ───────────────────────────────────────────────────────────

pub fn writeResponse(writer: *Io.Writer, resp: *const Response, head_only: bool) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ resp.status, resp.status_text });
    try writer.print("Content-Length: {d}\r\n", .{resp.body.length()});
    try writer.print("Content-Type: {s}\r\n", .{resp.content_type});
    try writer.writeAll("Connection: keep-alive\r\n");
    try writer.writeAll("Server: Simpaniz/0.1.1\r\n");
    for (resp.extra_headers) |h| {
        try writer.writeAll(h);
        if (!std.mem.endsWith(u8, h, "\r\n")) try writer.writeAll("\r\n");
    }
    try writer.writeAll("\r\n");

    if (head_only) return;

    switch (resp.body) {
        .none => {},
        .bytes => |b| if (b.len > 0) try writer.writeAll(b),
        .file => |fs| {
            // Seek to offset, stream `length` bytes.
            try fs.file.seekTo(fs.offset);
            var buf: [64 * 1024]u8 = undefined;
            var fr = fs.file.reader(&buf);
            try fr.interface.streamExact64(writer, fs.length);
        },
        .encrypted_file => |ef| {
            const sse = @import("storage/sse.zig");
            try ef.file.seekTo(0);
            var buf: [64 * 1024]u8 = undefined;
            var fr = ef.file.reader(&buf);
            try sse.decryptStream(&fr.interface, writer, ef.plaintext_length, &ef.dek);
        },
    }
}

pub fn writeError(writer: *Io.Writer, status: u16, status_text: []const u8, body: []const u8) void {
    writeResponse(writer, &.{
        .status = status,
        .status_text = status_text,
        .content_type = "application/xml",
        .body = .{ .bytes = body },
    }, false) catch {};
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "parseRequest basic GET" {
    var fbs = std.Io.Reader.fixed("GET /foo?bar=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n");
    const a = std.testing.allocator;
    var req = try parseRequest(&fbs, a, .{});
    defer req.deinit();
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/foo", req.path);
    try std.testing.expectEqualStrings("bar=1", req.query);
    try std.testing.expect(req.header("host") != null);
    try std.testing.expect(req.header("HOST") != null);
}

test "parseRequest URL-decoded path" {
    var fbs = std.Io.Reader.fixed("PUT /my-bucket/hello%20world HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    const a = std.testing.allocator;
    var req = try parseRequest(&fbs, a, .{});
    defer req.deinit();
    try std.testing.expectEqualStrings("/my-bucket/hello world", req.path);
    try std.testing.expectEqualStrings("/my-bucket/hello%20world", req.raw_path);
}

test "parseRequest streaming body" {
    var fbs = std.Io.Reader.fixed("PUT /b/k HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO");
    const a = std.testing.allocator;
    var req = try parseRequest(&fbs, a, .{});
    defer req.deinit();
    var buf: [16]u8 = undefined;
    const n = try req.readBody(&buf);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("HELLO", buf[0..5]);
}

test "parseRequest unsupported method" {
    var fbs = std.Io.Reader.fixed("FOO / HTTP/1.1\r\nHost: x\r\n\r\n");
    const a = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedMethod, parseRequest(&fbs, a, .{}));
}

test "parseRequest header limit" {
    var fbs = std.Io.Reader.fixed("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n");
    const a = std.testing.allocator;
    try std.testing.expectError(error.TooManyHeaders, parseRequest(&fbs, a, .{ .max_headers = 1 }));
}
