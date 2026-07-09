//! In-process TLS 1.3 server for simpaniz.
//!
//! Reuses every shared wire-format definition from `std.crypto.tls`
//! (record/content types, `HandshakeType`, `CipherSuite`, extension enums,
//! `hkdfExpandLabel`, the `HandshakeCipher`/`ApplicationCipher` key-schedule
//! unions) and mirrors the record-layer `std.Io.Reader`/`std.Io.Writer`
//! plumbing of `std.crypto.tls.Client` (`lib/std/crypto/tls/Client.zig`),
//! adapted for the server role.
//!
//! ponytail: TLS 1.3 only (reject 1.2). x25519 key exchange only, no
//! HelloRetryRequest — modern clients always send an x25519 key_share, so a
//! client that doesn't gets a handshake_failure alert instead of a retry
//! round trip. Server certificate must be ECDSA P-256 (PKCS#8 or SEC1 PEM).
//! No client certificates, no session resumption/0-RTT, no ALPN protocols
//! besides selecting "http/1.1" when offered.
const std = @import("std");
const tls = std.crypto.tls;
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Certificate = std.crypto.Certificate;

// ---------------------------------------------------------------------------
// ServerContext: loaded certificate chain + private key.
// ---------------------------------------------------------------------------

pub const ServerContext = struct {
    arena: std.heap.ArenaAllocator,
    cert_ders: [][]const u8,
    key: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,

    /// Loads a PEM certificate chain and matching PKCS#8/SEC1 P-256 private
    /// key. Paths are resolved relative to the current working directory (or
    /// absolute). Caller must call `deinit`.
    pub fn load(gpa: Allocator, cert_path: []const u8, key_path: []const u8) !*ServerContext {
        const self = try gpa.create(ServerContext);
        errdefer gpa.destroy(self);
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();

        const cert_pem = try std.fs.cwd().readFileAlloc(a, cert_path, 4 << 20);
        const key_pem = try std.fs.cwd().readFileAlloc(a, key_path, 4 << 20);

        const cert_blocks = try pemDecodeAll(a, cert_pem);
        var certs = std.ArrayList([]const u8){};
        for (cert_blocks) |b| {
            if (mem.eql(u8, b.label, "CERTIFICATE")) try certs.append(a, b.der);
        }
        if (certs.items.len == 0) return error.NoCertificatesFound;
        self.cert_ders = try certs.toOwnedSlice(a);

        const leaf: Certificate = .{ .buffer = self.cert_ders[0], .index = 0 };
        const leaf_parsed = leaf.parse() catch |err| {
            std.log.err("tls: failed to parse leaf certificate {s}: {}", .{ cert_path, err });
            return err;
        };

        const key_blocks = try pemDecodeAll(a, key_pem);
        if (key_blocks.len == 0) return error.NoPrivateKeyFound;
        const scalar = extractP256Scalar(key_blocks[0].der) catch |err| {
            std.log.err("tls: unsupported private key in {s} (only PKCS#8/SEC1 P-256 EC keys are supported): {}", .{ key_path, err });
            return err;
        };
        const secret = try crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar);
        self.key = crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch return error.UnsupportedKey;

        switch (leaf_parsed.pub_key_algo) {
            .X9_62_id_ecPublicKey => {
                const our = self.key.public_key.toUncompressedSec1();
                if (!mem.eql(u8, leaf_parsed.pubKey(), &our)) {
                    std.log.warn("tls: certificate public key does not match private key ({s} / {s})", .{ cert_path, key_path });
                }
            },
            else => std.log.warn("tls: leaf certificate is not an EC public key; skipping cert/key match check", .{}),
        }

        return self;
    }

    pub fn deinit(self: *ServerContext) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self);
    }
};

// ---------------------------------------------------------------------------
// PEM / DER helpers
// ---------------------------------------------------------------------------

pub const PemBlock = struct { label: []const u8, der: []u8 };

/// Decodes every `-----BEGIN X-----...-----END X-----` block in `text`. The
/// `label` fields borrow from `text`; `der` fields are allocated via `a`.
///
/// Exported (in addition to internal use above) so `acme.zig` can reuse the
/// same PEM/DER reading without duplicating it.
pub fn pemDecodeAll(a: Allocator, text: []const u8) ![]PemBlock {
    var blocks = std.ArrayList(PemBlock){};
    errdefer {
        for (blocks.items) |b| a.free(b.der);
        blocks.deinit(a);
    }
    var pos: usize = 0;
    while (mem.indexOfPos(u8, text, pos, "-----BEGIN ")) |begin_idx| {
        const label_start = begin_idx + "-----BEGIN ".len;
        const label_end = mem.indexOfPos(u8, text, label_start, "-----") orelse return error.InvalidPem;
        const label = text[label_start..label_end];
        const body_start = label_end + "-----".len;
        var end_needle_buf: [96]u8 = undefined;
        const end_needle = std.fmt.bufPrint(&end_needle_buf, "-----END {s}-----", .{label}) catch return error.InvalidPem;
        const end_idx = mem.indexOfPos(u8, text, body_start, end_needle) orelse return error.InvalidPem;
        const b64_raw = text[body_start..end_idx];

        var b64_stack: [16384]u8 = undefined;
        if (b64_raw.len > b64_stack.len) return error.PemTooLarge;
        var n: usize = 0;
        for (b64_raw) |c| {
            if (c == '\n' or c == '\r' or c == ' ' or c == '\t') continue;
            b64_stack[n] = c;
            n += 1;
        }
        const b64 = b64_stack[0..n];
        const dec = std.base64.standard.Decoder;
        const der_len = dec.calcSizeForSlice(b64) catch return error.InvalidPem;
        const der = try a.alloc(u8, der_len);
        errdefer a.free(der);
        dec.decode(der, b64) catch return error.InvalidPem;

        try blocks.append(a, .{ .label = label, .der = der });
        pos = end_idx + end_needle.len;
    }
    return blocks.toOwnedSlice(a);
}

const Tlv = struct { tag: u8, content: []const u8, next: usize };

/// Minimal DER TLV reader: definite-length SEQUENCE/INTEGER/OCTET STRING
/// headers only (everything this file needs to walk PKCS#8/SEC1 EC keys).
fn readTlv(buf: []const u8, pos: usize) error{InvalidPem}!Tlv {
    if (pos + 2 > buf.len) return error.InvalidPem;
    const tag = buf[pos];
    const len_byte = buf[pos + 1];
    var idx = pos + 2;
    var len: usize = undefined;
    if (len_byte & 0x80 == 0) {
        len = len_byte;
    } else {
        const nbytes = len_byte & 0x7f;
        if (nbytes == 0 or nbytes > 4 or idx + nbytes > buf.len) return error.InvalidPem;
        len = 0;
        for (0..nbytes) |i| len = (len << 8) | buf[idx + i];
        idx += nbytes;
    }
    if (idx + len > buf.len) return error.InvalidPem;
    return .{ .tag = tag, .content = buf[idx..][0..len], .next = idx + len };
}

/// Extracts the raw 32-byte P-256 private scalar from either a PKCS#8
/// `PrivateKeyInfo` (recurses once into the wrapped SEC1 `ECPrivateKey`) or a
/// bare SEC1 `ECPrivateKey` DER blob.
///
/// Exported so `acme.zig` can reload the account/domain keys it persists.
pub fn extractP256Scalar(der_bytes: []const u8) error{ InvalidPem, UnsupportedKey }![32]u8 {
    const outer = try readTlv(der_bytes, 0);
    if (outer.tag != 0x30) return error.UnsupportedKey; // SEQUENCE
    const content = outer.content;
    const ver = try readTlv(content, 0);
    if (ver.tag != 0x02) return error.UnsupportedKey; // INTEGER (version)
    const second = try readTlv(content, ver.next);
    switch (second.tag) {
        0x30 => {
            // PKCS#8: AlgorithmIdentifier SEQUENCE, then OCTET STRING
            // wrapping the inner SEC1 ECPrivateKey DER.
            const octet = try readTlv(content, second.next);
            if (octet.tag != 0x04) return error.UnsupportedKey;
            return extractP256Scalar(octet.content);
        },
        0x04 => {
            // SEC1 ECPrivateKey: this OCTET STRING is the raw scalar.
            if (second.content.len != 32) return error.UnsupportedKey;
            return second.content[0..32].*;
        },
        else => return error.UnsupportedKey,
    }
}

// ---------------------------------------------------------------------------
// Record-layer primitives shared by handshake and post-handshake code.
// ---------------------------------------------------------------------------

fn nonceFor(comptime P: type, iv: [P.AEAD.nonce_length]u8, seq: u64) [P.AEAD.nonce_length]u8 {
    const V = @Vector(P.AEAD.nonce_length, u8);
    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
    var seq_be: [8]u8 = undefined;
    mem.writeInt(u64, &seq_be, seq, .big);
    const operand: V = pad ++ seq_be;
    return @as(V, iv) ^ operand;
}

fn writeRecordCleartext(output: *Writer, ct: tls.ContentType, body: []const u8) !void {
    var hdr: [tls.record_header_len]u8 = undefined;
    hdr[0] = @intFromEnum(ct);
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    mem.writeInt(u16, hdr[3..5], @intCast(body.len), .big);
    try output.writeAll(&hdr);
    try output.writeAll(body);
}

/// Encrypts `content` as a single TLSCiphertext record (content must be
/// short enough that `content.len + 1 <= max_ciphertext_inner_record_len`)
/// and writes it directly to `output`.
fn encryptOneAndWrite(
    comptime P: type,
    output: *Writer,
    key: [P.AEAD.key_length]u8,
    iv: [P.AEAD.nonce_length]u8,
    seq: *u64,
    content: []const u8,
    inner_ct: tls.ContentType,
) !void {
    var plain_buf: [tls.max_ciphertext_inner_record_len]u8 = undefined;
    @memcpy(plain_buf[0..content.len], content);
    plain_buf[content.len] = @intFromEnum(inner_ct);
    const inner_len = content.len + 1;
    const cipher_len = inner_len + P.AEAD.tag_length;

    var hdr: [tls.record_header_len]u8 = undefined;
    hdr[0] = @intFromEnum(tls.ContentType.application_data);
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    mem.writeInt(u16, hdr[3..5], @intCast(cipher_len), .big);

    const nonce = nonceFor(P, iv, seq.*);
    var out_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    @memcpy(out_buf[0..tls.record_header_len], &hdr);
    P.AEAD.encrypt(
        out_buf[tls.record_header_len..][0..inner_len],
        out_buf[tls.record_header_len + inner_len ..][0..P.AEAD.tag_length],
        plain_buf[0..inner_len],
        &hdr,
        nonce,
        key,
    );
    seq.* += 1;
    try output.writeAll(out_buf[0 .. tls.record_header_len + cipher_len]);
}

/// Chunks and encrypts a (possibly multi-message) handshake flight across as
/// many records as needed.
fn encryptAndWrite(
    comptime P: type,
    output: *Writer,
    key: [P.AEAD.key_length]u8,
    iv: [P.AEAD.nonce_length]u8,
    seq: *u64,
    cleartext: []const u8,
    inner_ct: tls.ContentType,
) !void {
    var off: usize = 0;
    while (off < cleartext.len) {
        const chunk = @min(cleartext.len - off, tls.max_ciphertext_inner_record_len - 1);
        try encryptOneAndWrite(P, output, key, iv, seq, cleartext[off..][0..chunk], inner_ct);
        off += chunk;
    }
}

fn decryptInto(
    comptime P: type,
    key: [P.AEAD.key_length]u8,
    iv: [P.AEAD.nonce_length]u8,
    seq: *u64,
    header: [tls.record_header_len]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (ciphertext.len < P.AEAD.tag_length) return error.TlsRecordOverflow;
    const inner_len = ciphertext.len - P.AEAD.tag_length;
    if (inner_len > out.len) return error.TlsRecordOverflow;
    const auth_tag = ciphertext[inner_len..][0..P.AEAD.tag_length];
    const nonce = nonceFor(P, iv, seq.*);
    P.AEAD.decrypt(out[0..inner_len], ciphertext[0..inner_len], auth_tag.*, &header, nonce, key) catch return error.TlsBadRecordMac;
    seq.* += 1;
    return inner_len;
}

fn readRawRecord(input: *Reader) !struct { ct: tls.ContentType, header: [tls.record_header_len]u8, body: []u8 } {
    const peeked = input.peek(tls.record_header_len) catch |err| switch (err) {
        error.EndOfStream => return error.TlsConnectionTruncated,
        error.ReadFailed => return error.ReadFailed,
    };
    var header: [tls.record_header_len]u8 = undefined;
    @memcpy(&header, peeked[0..tls.record_header_len]);
    const ct: tls.ContentType = @enumFromInt(header[0]);
    const record_len = mem.readInt(u16, header[3..5], .big);
    if (record_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;
    input.toss(tls.record_header_len);
    const body = input.take(record_len) catch |err| switch (err) {
        error.EndOfStream => return error.TlsConnectionTruncated,
        error.ReadFailed => return error.ReadFailed,
    };
    return .{ .ct = ct, .header = header, .body = body };
}

fn alertToError(body: []const u8) anyerror {
    if (body.len != 2) return error.TlsDecodeError;
    const desc: tls.Alert.Description = @enumFromInt(body[1]);
    desc.toError() catch |e| return e;
    // close_notify / user_canceled received mid-handshake: treat as an
    // unexpected premature close rather than a clean shutdown.
    return error.TlsConnectionTruncated;
}

fn mapErrToAlert(err: anyerror) tls.Alert.Description {
    return switch (err) {
        error.UnsupportedClientVersion => .protocol_version,
        error.NoSharedCipherSuite, error.NoX25519KeyShare => .handshake_failure,
        error.TlsDecodeError, error.TlsBadLength => .decode_error,
        error.TlsBadRecordMac, error.TlsDecryptError => .bad_record_mac,
        error.TlsIllegalParameter => .illegal_parameter,
        error.TlsUnexpectedMessage => .unexpected_message,
        error.TlsRecordOverflow => .record_overflow,
        else => .internal_error,
    };
}

fn sendAlertCleartext(output: *Writer, desc: tls.Alert.Description) void {
    const body = [_]u8{ @intFromEnum(tls.Alert.Level.fatal), @intFromEnum(desc) };
    writeRecordCleartext(output, .alert, &body) catch return;
    output.flush() catch return;
}

// ---------------------------------------------------------------------------
// Handshake driver
// ---------------------------------------------------------------------------

/// Reads (possibly record-fragmented) cleartext handshake records from
/// `input` until a complete ClientHello has been buffered into `buf`, and
/// returns the full handshake message (4-byte header + body).
fn readClientHelloRaw(input: *Reader, buf: []u8) ![]u8 {
    var have: usize = 0;
    while (true) {
        const rec = try readRawRecord(input);
        switch (rec.ct) {
            .change_cipher_spec => continue,
            .alert => return alertToError(rec.body),
            .handshake => {
                if (have + rec.body.len > buf.len) return error.TlsRecordOverflow;
                @memcpy(buf[have..][0..rec.body.len], rec.body);
                have += rec.body.len;
            },
            else => return error.TlsUnexpectedMessage,
        }
        if (have >= 4) {
            const declared: usize = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | buf[3];
            if (have >= 4 + declared) {
                if (buf[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.TlsUnexpectedMessage;
                return buf[0 .. 4 + declared];
            }
        }
    }
}

/// Parses ClientHello, negotiates cipher suite / x25519 key share / ALPN,
/// then dispatches into the comptime-specialized handshake continuation.
fn doHandshake(input: *Reader, output: *Writer, srv: *ServerContext) !tls.ApplicationCipher {
    var hs_buf: [tls.max_ciphertext_inner_record_len]u8 = undefined;
    const client_hello_msg = try readClientHelloRaw(input, &hs_buf);
    const body = client_hello_msg[4..];

    var d: tls.Decoder = .fromTheirSlice(body);
    try d.ensure(2 + 32 + 1);
    _ = d.decode(u16); // legacy_version
    d.skip(32); // client_random (covered by transcript hash over raw bytes)
    const sid_len = d.decode(u8);
    try d.ensure(sid_len);
    const legacy_session_id = d.slice(sid_len);
    try d.ensure(2);
    const cs_len = d.decode(u16);
    var csd = try d.sub(cs_len);
    var chosen_suite: ?tls.CipherSuite = null;
    while (!csd.eof()) {
        try csd.ensure(2);
        const cs = csd.decode(tls.CipherSuite);
        if (chosen_suite == null) {
            switch (cs) {
                .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 => chosen_suite = cs,
                else => {},
            }
        }
    }
    try d.ensure(1);
    const comp_len = d.decode(u8);
    try d.ensure(comp_len);
    d.skip(comp_len);

    var client_x25519_pub: ?[32]u8 = null;
    var saw_tls13 = false;
    var alpn_http11 = false;
    if (!d.eof()) {
        try d.ensure(2);
        const ext_total = d.decode(u16);
        var extd = try d.sub(ext_total);
        while (!extd.eof()) {
            try extd.ensure(4);
            const et = extd.decode(tls.ExtensionType);
            const elen = extd.decode(u16);
            var one = try extd.sub(elen);
            switch (et) {
                .supported_versions => {
                    try one.ensure(1);
                    const n = one.decode(u8);
                    try one.ensure(n);
                    var i: usize = 0;
                    while (i < n) : (i += 2) {
                        const v = one.decode(u16);
                        if (v == @intFromEnum(tls.ProtocolVersion.tls_1_3)) saw_tls13 = true;
                    }
                },
                .key_share => {
                    try one.ensure(2);
                    const n = one.decode(u16);
                    var ksd = try one.sub(n);
                    while (!ksd.eof()) {
                        try ksd.ensure(4);
                        const g = ksd.decode(tls.NamedGroup);
                        const klen = ksd.decode(u16);
                        try ksd.ensure(klen);
                        const kbytes = ksd.slice(klen);
                        if (g == .x25519 and klen == 32 and client_x25519_pub == null) {
                            client_x25519_pub = kbytes[0..32].*;
                        }
                    }
                },
                .application_layer_protocol_negotiation => {
                    try one.ensure(2);
                    const listlen = one.decode(u16);
                    var ad = try one.sub(listlen);
                    while (!ad.eof()) {
                        try ad.ensure(1);
                        const plen = ad.decode(u8);
                        try ad.ensure(plen);
                        const proto = ad.slice(plen);
                        if (mem.eql(u8, proto, "http/1.1")) alpn_http11 = true;
                    }
                },
                else => {},
            }
        }
    }

    if (!saw_tls13) return error.UnsupportedClientVersion;
    const suite = chosen_suite orelse return error.NoSharedCipherSuite;
    // ponytail: no HelloRetryRequest — modern clients always offer an
    // x25519 share, so we just fail the handshake instead of round-tripping.
    const client_pub = client_x25519_pub orelse return error.NoX25519KeyShare;

    var scratch_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch_state.deinit();
    const sa = scratch_state.allocator();

    const our_kp = crypto.dh.X25519.KeyPair.generate();
    const shared = crypto.dh.X25519.scalarmult(our_kp.secret_key, client_pub) catch return error.NoX25519KeyShare;

    switch (suite) {
        inline .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 => |tag| {
            return doHandshakeForSuite(tag, input, output, srv, client_hello_msg, legacy_session_id, suite, shared, our_kp, alpn_http11, sa);
        },
        else => unreachable, // filtered above
    }
}

fn doHandshakeForSuite(
    comptime tag: tls.CipherSuite,
    input: *Reader,
    output: *Writer,
    srv: *ServerContext,
    client_hello_msg: []const u8,
    legacy_session_id: []const u8,
    suite: tls.CipherSuite,
    shared: [32]u8,
    our_kp: crypto.dh.X25519.KeyPair,
    alpn_http11: bool,
    sa: Allocator,
) !tls.ApplicationCipher {
    var hc = @unionInit(tls.HandshakeCipher, @tagName(tag), .{
        .transcript_hash = .init(.{}),
        .version = undefined,
    });
    const p = &@field(hc, @tagName(tag));
    const P = @TypeOf(p.*).A;

    p.transcript_hash.update(client_hello_msg);

    // ---- ServerHello ----
    var server_random: [32]u8 = undefined;
    crypto.random.bytes(&server_random);

    var sh_body = std.ArrayList(u8){};
    try sh_body.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)));
    try sh_body.appendSlice(sa, &server_random);
    try sh_body.append(sa, @intCast(legacy_session_id.len));
    try sh_body.appendSlice(sa, legacy_session_id);
    try sh_body.appendSlice(sa, &tls.int(u16, @intFromEnum(suite)));
    try sh_body.append(sa, 0); // legacy_compression_method

    var sh_ext = std.ArrayList(u8){};
    try sh_ext.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.ExtensionType.supported_versions)));
    try sh_ext.appendSlice(sa, &tls.int(u16, 2));
    try sh_ext.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_3)));
    try sh_ext.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.ExtensionType.key_share)));
    try sh_ext.appendSlice(sa, &tls.int(u16, 2 + 2 + 32));
    try sh_ext.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.NamedGroup.x25519)));
    try sh_ext.appendSlice(sa, &tls.int(u16, 32));
    try sh_ext.appendSlice(sa, &our_kp.public_key);

    try sh_body.appendSlice(sa, &tls.int(u16, @intCast(sh_ext.items.len)));
    try sh_body.appendSlice(sa, sh_ext.items);

    var sh_msg = std.ArrayList(u8){};
    try sh_msg.append(sa, @intFromEnum(tls.HandshakeType.server_hello));
    try sh_msg.appendSlice(sa, &tls.int(u24, @intCast(sh_body.items.len)));
    try sh_msg.appendSlice(sa, sh_body.items);

    p.transcript_hash.update(sh_msg.items);

    try writeRecordCleartext(output, .handshake, sh_msg.items);
    // Middlebox-compatibility change_cipher_spec (RFC 8446 4.1.2): required
    // because the client always sends a non-empty legacy_session_id.
    try writeRecordCleartext(output, .change_cipher_spec, &.{@intFromEnum(tls.ChangeCipherSpecType.change_cipher_spec)});
    try output.flush();

    // ---- Handshake secrets ----
    const hello_hash = p.transcript_hash.peek();
    const zeroes = [1]u8{0} ** P.Hash.digest_length;
    const early_secret = P.Hkdf.extract(&[1]u8{0}, &zeroes);
    const empty_hash = tls.emptyHash(P.Hash);
    p.version = .{ .tls_1_3 = undefined };
    const pv = &p.version.tls_1_3;
    const hs_derived_secret = tls.hkdfExpandLabel(P.Hkdf, early_secret, "derived", &empty_hash, P.Hash.digest_length);
    pv.handshake_secret = P.Hkdf.extract(&hs_derived_secret, &shared);
    const ap_derived_secret = tls.hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "derived", &empty_hash, P.Hash.digest_length);
    pv.master_secret = P.Hkdf.extract(&ap_derived_secret, &zeroes);
    const client_hs_secret = tls.hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "c hs traffic", &hello_hash, P.Hash.digest_length);
    const server_hs_secret = tls.hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "s hs traffic", &hello_hash, P.Hash.digest_length);
    pv.client_finished_key = tls.hkdfExpandLabel(P.Hkdf, client_hs_secret, "finished", "", P.Hmac.key_length);
    pv.server_finished_key = tls.hkdfExpandLabel(P.Hkdf, server_hs_secret, "finished", "", P.Hmac.key_length);
    pv.client_handshake_key = tls.hkdfExpandLabel(P.Hkdf, client_hs_secret, "key", "", P.AEAD.key_length);
    pv.server_handshake_key = tls.hkdfExpandLabel(P.Hkdf, server_hs_secret, "key", "", P.AEAD.key_length);
    pv.client_handshake_iv = tls.hkdfExpandLabel(P.Hkdf, client_hs_secret, "iv", "", P.AEAD.nonce_length);
    pv.server_handshake_iv = tls.hkdfExpandLabel(P.Hkdf, server_hs_secret, "iv", "", P.AEAD.nonce_length);

    // ---- EncryptedExtensions ----
    var ee_ext = std.ArrayList(u8){};
    if (alpn_http11) {
        try ee_ext.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)));
        try ee_ext.appendSlice(sa, &tls.int(u16, 2 + 1 + 8));
        try ee_ext.appendSlice(sa, &tls.int(u16, 1 + 8));
        try ee_ext.append(sa, 8);
        try ee_ext.appendSlice(sa, "http/1.1");
    }
    var ee_body = std.ArrayList(u8){};
    try ee_body.appendSlice(sa, &tls.int(u16, @intCast(ee_ext.items.len)));
    try ee_body.appendSlice(sa, ee_ext.items);
    var ee_msg = std.ArrayList(u8){};
    try ee_msg.append(sa, @intFromEnum(tls.HandshakeType.encrypted_extensions));
    try ee_msg.appendSlice(sa, &tls.int(u24, @intCast(ee_body.items.len)));
    try ee_msg.appendSlice(sa, ee_body.items);

    // ---- Certificate ----
    var certs_body = std.ArrayList(u8){};
    for (srv.cert_ders) |c| {
        try certs_body.appendSlice(sa, &tls.int(u24, @intCast(c.len)));
        try certs_body.appendSlice(sa, c);
        try certs_body.appendSlice(sa, &tls.int(u16, 0)); // no per-cert extensions
    }
    var cert_body = std.ArrayList(u8){};
    try cert_body.append(sa, 0); // certificate_request_context
    try cert_body.appendSlice(sa, &tls.int(u24, @intCast(certs_body.items.len)));
    try cert_body.appendSlice(sa, certs_body.items);
    var cert_msg = std.ArrayList(u8){};
    try cert_msg.append(sa, @intFromEnum(tls.HandshakeType.certificate));
    try cert_msg.appendSlice(sa, &tls.int(u24, @intCast(cert_body.items.len)));
    try cert_msg.appendSlice(sa, cert_body.items);

    p.transcript_hash.update(ee_msg.items);
    p.transcript_hash.update(cert_msg.items);

    // ---- CertificateVerify ----
    const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
    const th_for_cv = p.transcript_hash.peek();
    var cv_msg_content = std.ArrayList(u8){};
    try cv_msg_content.appendSlice(sa, " " ** 64);
    try cv_msg_content.appendSlice(sa, "TLS 1.3, server CertificateVerify");
    try cv_msg_content.append(sa, 0);
    try cv_msg_content.appendSlice(sa, &th_for_cv);
    const sig = srv.key.sign(cv_msg_content.items, null) catch return error.SigningFailed;
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_buf);

    var cv_body = std.ArrayList(u8){};
    try cv_body.appendSlice(sa, &tls.int(u16, @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256)));
    try cv_body.appendSlice(sa, &tls.int(u16, @intCast(der_sig.len)));
    try cv_body.appendSlice(sa, der_sig);
    var cv_msg = std.ArrayList(u8){};
    try cv_msg.append(sa, @intFromEnum(tls.HandshakeType.certificate_verify));
    try cv_msg.appendSlice(sa, &tls.int(u24, @intCast(cv_body.items.len)));
    try cv_msg.appendSlice(sa, cv_body.items);

    p.transcript_hash.update(cv_msg.items);

    // ---- Finished ----
    const finished_digest = p.transcript_hash.peek();
    const verify_data = tls.hmac(P.Hmac, &finished_digest, pv.server_finished_key);
    var fin_msg = std.ArrayList(u8){};
    try fin_msg.append(sa, @intFromEnum(tls.HandshakeType.finished));
    try fin_msg.appendSlice(sa, &tls.int(u24, @intCast(verify_data.len)));
    try fin_msg.appendSlice(sa, &verify_data);

    p.transcript_hash.update(fin_msg.items);
    const handshake_hash = p.transcript_hash.finalResult();

    // ---- Send flight: EE + Certificate + CertificateVerify + Finished ----
    var flight = std.ArrayList(u8){};
    try flight.appendSlice(sa, ee_msg.items);
    try flight.appendSlice(sa, cert_msg.items);
    try flight.appendSlice(sa, cv_msg.items);
    try flight.appendSlice(sa, fin_msg.items);
    var server_write_seq: u64 = 0;
    try encryptAndWrite(P, output, pv.server_handshake_key, pv.server_handshake_iv, &server_write_seq, flight.items, .handshake);
    try output.flush();

    // ---- Read + verify client Finished (encrypted under client hs keys) ----
    var client_read_seq: u64 = 0;
    var fbuf: [512]u8 = undefined;
    var have: usize = 0;
    while (true) {
        const rec = try readRawRecord(input);
        switch (rec.ct) {
            .change_cipher_spec => continue,
            .alert => return alertToError(rec.body),
            .application_data => {
                var plain: [tls.max_ciphertext_inner_record_len]u8 = undefined;
                const inner_len = try decryptInto(P, pv.client_handshake_key, pv.client_handshake_iv, &client_read_seq, rec.header, rec.body, &plain);
                const trimmed = mem.trimRight(u8, plain[0..inner_len], "\x00");
                if (trimmed.len == 0) return error.TlsDecodeError;
                const inner_ct: tls.ContentType = @enumFromInt(trimmed[trimmed.len - 1]);
                const content = trimmed[0 .. trimmed.len - 1];
                if (inner_ct == .alert) return alertToError(content);
                if (inner_ct != .handshake) return error.TlsUnexpectedMessage;
                if (have + content.len > fbuf.len) return error.TlsRecordOverflow;
                @memcpy(fbuf[have..][0..content.len], content);
                have += content.len;
            },
            else => return error.TlsUnexpectedMessage,
        }
        if (have >= 4) {
            const declared: usize = (@as(usize, fbuf[1]) << 16) | (@as(usize, fbuf[2]) << 8) | fbuf[3];
            if (have >= 4 + declared) {
                if (fbuf[0] != @intFromEnum(tls.HandshakeType.finished)) return error.TlsUnexpectedMessage;
                const client_verify_data = fbuf[4 .. 4 + declared];
                const expected = tls.hmac(P.Hmac, &handshake_hash, pv.client_finished_key);
                if (client_verify_data.len != expected.len or !mem.eql(u8, client_verify_data, &expected)) {
                    return error.TlsDecryptError;
                }
                break;
            }
        }
    }

    // ---- Application traffic secrets ----
    const client_ap_secret = tls.hkdfExpandLabel(P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
    const server_ap_secret = tls.hkdfExpandLabel(P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
    return @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_3 = .{
        .client_secret = client_ap_secret,
        .server_secret = server_ap_secret,
        .client_key = tls.hkdfExpandLabel(P.Hkdf, client_ap_secret, "key", "", P.AEAD.key_length),
        .server_key = tls.hkdfExpandLabel(P.Hkdf, server_ap_secret, "key", "", P.AEAD.key_length),
        .client_iv = tls.hkdfExpandLabel(P.Hkdf, client_ap_secret, "iv", "", P.AEAD.nonce_length),
        .server_iv = tls.hkdfExpandLabel(P.Hkdf, server_ap_secret, "iv", "", P.AEAD.nonce_length),
    } });
}

// ---------------------------------------------------------------------------
// Connection: post-handshake record layer, exposed as Io.Reader/Io.Writer.
// ---------------------------------------------------------------------------

pub const Connection = struct {
    net_reader: std.net.Stream.Reader,
    net_writer: std.net.Stream.Writer,
    /// Decrypted stream from the client to the server.
    reader: Reader,
    /// Plaintext stream from the server to the client (encrypted on flush/drain).
    writer: Writer,
    application_cipher: tls.ApplicationCipher,
    read_seq: u64,
    write_seq: u64,
    received_close_notify: bool,
    read_err: ?ReadError = null,

    pub const ReadError = error{
        TlsAlert,
        TlsBadLength,
        TlsBadRecordMac,
        TlsConnectionTruncated,
        TlsDecodeError,
        TlsRecordOverflow,
        TlsUnexpectedMessage,
        TlsIllegalParameter,
        TlsSequenceOverflow,
    };

    /// Minimum size required for `net_read_buf`/`net_write_buf` (the raw,
    /// encrypted-record buffers — distinct from the plaintext buffers).
    pub const min_net_buffer_len = tls.max_ciphertext_record_len;

    /// Minimum size required for `plain_read_buf`: a single record can
    /// decrypt to up to `max_ciphertext_len - AEAD tag` bytes, which must fit
    /// in the plaintext reader buffer in one piece.
    pub const min_plain_read_buffer_len = tls.max_ciphertext_len;

    /// Performs the full server-side TLS 1.3 handshake, blocking on `stream`.
    /// `net_read_buf`/`net_write_buf` must be at least `min_net_buffer_len`;
    /// `plain_read_buf`/`plain_write_buf` back the exposed `reader`/`writer`.
    pub fn accept(
        stream: std.net.Stream,
        srv: *ServerContext,
        net_read_buf: []u8,
        net_write_buf: []u8,
        plain_read_buf: []u8,
        plain_write_buf: []u8,
    ) !Connection {
        assert(net_read_buf.len >= min_net_buffer_len);
        assert(net_write_buf.len >= min_net_buffer_len);

        var net_reader = stream.reader(net_read_buf);
        var net_writer = stream.writer(net_write_buf);
        const input = net_reader.interface();
        const output = &net_writer.interface;

        const app_cipher = doHandshake(input, output, srv) catch |err| {
            sendAlertCleartext(output, mapErrToAlert(err));
            return err;
        };

        return .{
            .net_reader = net_reader,
            .net_writer = net_writer,
            .reader = .{
                .buffer = plain_read_buf,
                .vtable = &.{ .stream = readerStream, .readVec = readerReadVec },
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .buffer = plain_write_buf,
                .vtable = &.{ .drain = writerDrain, .flush = writerFlush },
            },
            .application_cipher = app_cipher,
            .read_seq = 0,
            .write_seq = 0,
            .received_close_notify = false,
        };
    }

    /// Best-effort close_notify; caller still closes the underlying socket.
    pub fn close(self: *Connection) void {
        if (self.received_close_notify) return;
        self.writer.flush() catch {};
        switch (self.application_cipher) {
            inline else => |*p| {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const output = &self.net_writer.interface;
                encryptOneAndWrite(P, output, pv.server_key, pv.server_iv, &self.write_seq, &tls.close_notify_alert, .alert) catch return;
                output.flush() catch return;
            },
        }
    }

    fn prepareCiphertextRecord(
        self: *Connection,
        ciphertext_buf: []u8,
        bytes: []const u8,
        inner_content_type: tls.ContentType,
    ) struct { ciphertext_end: usize, cleartext_len: usize } {
        var cleartext_buf: [tls.max_ciphertext_len]u8 = undefined;
        var ciphertext_end: usize = 0;
        var bytes_i: usize = 0;
        switch (self.application_cipher) {
            inline else => |*p| {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.AEAD.tag_length + 1;
                while (true) {
                    const encrypted_content_len: u16 = @intCast(@min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    ));
                    if (encrypted_content_len == 0) return .{ .ciphertext_end = ciphertext_end, .cleartext_len = bytes_i };

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @intFromEnum(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const inner_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..inner_len];

                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad[0] = @intFromEnum(tls.ContentType.application_data);
                    ad[1] = 0x03;
                    ad[2] = 0x03;
                    mem.writeInt(u16, ad[3..5], @intCast(inner_len + P.AEAD.tag_length), .big);
                    ciphertext_end += ad.len;

                    const ciphertext = ciphertext_buf[ciphertext_end..][0..inner_len];
                    ciphertext_end += inner_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;

                    const nonce = nonceFor(P, pv.server_iv, self.write_seq);
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.server_key);
                    // ponytail: no automatic KeyUpdate on sequence overflow
                    // (u64 wrap is not reachable in practice).
                    self.write_seq += 1;
                }
            },
        }
    }
};

fn sendKeyUpdateNotRequested(self: *Connection) !void {
    const output = &self.net_writer.interface;
    const msg = [_]u8{@intFromEnum(tls.KeyUpdateRequest.update_not_requested)};
    switch (self.application_cipher) {
        inline else => |*p| {
            const pv = &p.tls_1_3;
            const P = @TypeOf(p.*);
            try encryptOneAndWrite(P, output, pv.server_key, pv.server_iv, &self.write_seq, &msg, .handshake);
        },
    }
    try output.flush();
}

fn selfRebase(r: *Reader, capacity: usize) void {
    if (r.buffer.len - r.end >= capacity) return;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    assert(r.buffer.len - r.end >= capacity);
}

fn failRead(self: *Connection, err: Connection.ReadError) error{ReadFailed} {
    self.read_err = err;
    return error.ReadFailed;
}

fn readerStream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    _ = w;
    _ = limit;
    const self: *Connection = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(self);
}

fn readerReadVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    _ = data;
    const self: *Connection = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(self);
}

fn readIndirect(self: *Connection) Reader.Error!usize {
    const r = &self.reader;
    if (self.received_close_notify) return error.EndOfStream;
    const input = self.net_reader.interface();

    const header = input.peek(tls.record_header_len) catch |err| switch (err) {
        error.EndOfStream => return failRead(self, error.TlsConnectionTruncated),
        error.ReadFailed => return error.ReadFailed,
    };
    const ct: tls.ContentType = @enumFromInt(header[0]);
    const record_len = mem.readInt(u16, header[3..5], .big);
    if (record_len > tls.max_ciphertext_len) return failRead(self, error.TlsRecordOverflow);
    const record_end = tls.record_header_len + record_len;
    if (record_end > input.buffered().len) {
        input.fillMore() catch |err| switch (err) {
            error.EndOfStream => return failRead(self, error.TlsConnectionTruncated),
            error.ReadFailed => return error.ReadFailed,
        };
        if (record_end > input.buffered().len) return 0;
    }

    if (ct == .change_cipher_spec) {
        _ = input.take(record_end) catch unreachable; // already buffered above
        return 0;
    }
    if (ct != .application_data) return failRead(self, error.TlsUnexpectedMessage);

    const cleartext_len, const inner_ct: tls.ContentType = cleartext: switch (self.application_cipher) {
        inline else => |*p| {
            const pv = &p.tls_1_3;
            const P = @TypeOf(p.*);
            const ad = input.take(tls.record_header_len) catch unreachable; // already peeked
            if (record_len < P.AEAD.tag_length) return failRead(self, error.TlsRecordOverflow);
            const ciphertext_len = record_len - P.AEAD.tag_length;
            const ciphertext = input.take(ciphertext_len) catch unreachable; // already peeked
            const auth_tag = (input.takeArray(P.AEAD.tag_length) catch unreachable).*; // already peeked
            const nonce = nonceFor(P, pv.client_iv, self.read_seq);
            selfRebase(r, ciphertext.len);
            const cleartext = r.buffer[r.end..][0..ciphertext.len];
            P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.client_key) catch
                return failRead(self, error.TlsBadRecordMac);
            const msg = mem.trimRight(u8, cleartext, "\x00");
            if (msg.len == 0) return failRead(self, error.TlsDecodeError);
            break :cleartext .{ msg.len - 1, @as(tls.ContentType, @enumFromInt(msg[msg.len - 1])) };
        },
    };
    const cleartext = r.buffer[r.end..][0..cleartext_len];
    self.read_seq = std.math.add(u64, self.read_seq, 1) catch return failRead(self, error.TlsSequenceOverflow);

    switch (inner_ct) {
        .alert => {
            if (cleartext.len != 2) return failRead(self, error.TlsDecodeError);
            const alert: tls.Alert = .{ .level = @enumFromInt(cleartext[0]), .description = @enumFromInt(cleartext[1]) };
            switch (alert.description) {
                .close_notify => {
                    self.received_close_notify = true;
                    return 0;
                },
                .user_canceled => return failRead(self, error.TlsUnexpectedMessage),
                else => return failRead(self, error.TlsAlert),
            }
        },
        .handshake => {
            var ct_i: usize = 0;
            while (true) {
                if (ct_i + 4 > cleartext.len) return failRead(self, error.TlsBadLength);
                const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                ct_i += 1;
                const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                ct_i += 3;
                const next_i = ct_i + handshake_len;
                if (next_i > cleartext.len) return failRead(self, error.TlsBadLength);
                const handshake = cleartext[ct_i..next_i];
                switch (handshake_type) {
                    .key_update => {
                        if (handshake.len != 1) return failRead(self, error.TlsDecodeError);
                        switch (self.application_cipher) {
                            inline else => |*p| {
                                const pv = &p.tls_1_3;
                                const P = @TypeOf(p.*);
                                const new_client_secret = tls.hkdfExpandLabel(P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length);
                                pv.client_secret = new_client_secret;
                                pv.client_key = tls.hkdfExpandLabel(P.Hkdf, new_client_secret, "key", "", P.AEAD.key_length);
                                pv.client_iv = tls.hkdfExpandLabel(P.Hkdf, new_client_secret, "iv", "", P.AEAD.nonce_length);
                            },
                        }
                        self.read_seq = 0;
                        switch (@as(tls.KeyUpdateRequest, @enumFromInt(handshake[0]))) {
                            .update_requested => {
                                switch (self.application_cipher) {
                                    inline else => |*p| {
                                        const pv = &p.tls_1_3;
                                        const P = @TypeOf(p.*);
                                        const new_server_secret = tls.hkdfExpandLabel(P.Hkdf, pv.server_secret, "traffic upd", "", P.Hash.digest_length);
                                        pv.server_secret = new_server_secret;
                                        pv.server_key = tls.hkdfExpandLabel(P.Hkdf, new_server_secret, "key", "", P.AEAD.key_length);
                                        pv.server_iv = tls.hkdfExpandLabel(P.Hkdf, new_server_secret, "iv", "", P.AEAD.nonce_length);
                                    },
                                }
                                self.write_seq = 0;
                                sendKeyUpdateNotRequested(self) catch {};
                            },
                            .update_not_requested => {},
                            _ => return failRead(self, error.TlsIllegalParameter),
                        }
                    },
                    .new_session_ticket => {}, // we never send one; tolerate stray ones
                    else => return failRead(self, error.TlsUnexpectedMessage),
                }
                ct_i = next_i;
                if (ct_i >= cleartext.len) break;
            }
            return 0;
        },
        .application_data => {
            r.end += cleartext.len;
            return 0;
        },
        else => return failRead(self, error.TlsUnexpectedMessage),
    }
}

fn writerDrain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const self: *Connection = @alignCast(@fieldParentPtr("writer", w));
    const output = &self.net_writer.interface;
    const ciphertext_buf = try output.writableSliceGreedy(Connection.min_net_buffer_len);
    var ciphertext_end: usize = 0;
    var total_clear: usize = 0;
    done: {
        {
            const buf = w.buffered();
            const prepared = self.prepareCiphertextRecord(ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        for (data[0 .. data.len - 1]) |buf| {
            const prepared = self.prepareCiphertextRecord(ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        const buf = data[data.len - 1];
        for (0..splat) |_| {
            const prepared = self.prepareCiphertextRecord(ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
    }
    output.advance(ciphertext_end);
    return w.consume(total_clear);
}

fn writerFlush(w: *Writer) Writer.Error!void {
    const self: *Connection = @alignCast(@fieldParentPtr("writer", w));
    const output = &self.net_writer.interface;
    const ciphertext_buf = try output.writableSliceGreedy(Connection.min_net_buffer_len);
    const prepared = self.prepareCiphertextRecord(ciphertext_buf, w.buffered(), .application_data);
    output.advance(prepared.ciphertext_end);
    w.end = 0;
    // Unlike std.crypto.tls.Client (whose caller is expected to flush the
    // underlying stream separately), simpaniz's HTTP loop only ever calls
    // `writer.flush()`, so this must push all the way to the socket.
    try output.flush();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "tls_server: PEM decode and P-256 key/cert parse" {
    const gpa = std.testing.allocator;
    const key_pem = std.fs.cwd().readFileAlloc(gpa, "testdata/tls_key.pem", 1 << 16) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer gpa.free(key_pem);
    const key_blocks = try pemDecodeAll(gpa, key_pem);
    defer {
        for (key_blocks) |b| gpa.free(b.der);
        gpa.free(key_blocks);
    }
    try std.testing.expect(key_blocks.len >= 1);
    const scalar = try extractP256Scalar(key_blocks[0].der);
    _ = try crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar);

    const cert_pem = std.fs.cwd().readFileAlloc(gpa, "testdata/tls_cert.pem", 1 << 16) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer gpa.free(cert_pem);
    const cert_blocks = try pemDecodeAll(gpa, cert_pem);
    defer {
        for (cert_blocks) |b| gpa.free(b.der);
        gpa.free(cert_blocks);
    }
    try std.testing.expect(cert_blocks.len >= 1);
    const leaf: Certificate = .{ .buffer = cert_blocks[0].der, .index = 0 };
    _ = try leaf.parse();
}

test "tls_server: loopback handshake interop with std.crypto.tls.Client" {
    const gpa = std.testing.allocator;
    const srv = ServerContext.load(gpa, "testdata/tls_cert.pem", "testdata/tls_key.pem") catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer srv.deinit();

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const bound = listener.listen_address;

    const Ctx = struct {
        listener: *std.net.Server,
        srv: *ServerContext,
        ok: std.atomic.Value(bool) = .init(false),
    };
    var ctx: Ctx = .{ .listener = &listener, .srv = srv };

    const server_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *Ctx) void {
            const conn = c.listener.accept() catch |err| {
                std.log.err("test tls server: accept failed: {}", .{err});
                return;
            };
            defer conn.stream.close();
            var net_read_buf: [Connection.min_net_buffer_len]u8 = undefined;
            var net_write_buf: [Connection.min_net_buffer_len]u8 = undefined;
            var plain_read_buf: [Connection.min_plain_read_buffer_len]u8 = undefined;
            var plain_write_buf: [4096]u8 = undefined;
            var tconn = Connection.accept(conn.stream, c.srv, &net_read_buf, &net_write_buf, &plain_read_buf, &plain_write_buf) catch |err| {
                std.log.err("test tls server: handshake failed: {}", .{err});
                return;
            };
            defer tconn.close();
            var buf: [13]u8 = undefined;
            tconn.reader.readSliceAll(&buf) catch |err| {
                std.log.err("test tls server: read failed: {}", .{err});
                return;
            };
            tconn.writer.writeAll(&buf) catch |err| {
                std.log.err("test tls server: write failed: {}", .{err});
                return;
            };
            tconn.writer.flush() catch |err| {
                std.log.err("test tls server: flush failed: {}", .{err});
                return;
            };
            c.ok.store(true, .seq_cst);
        }
    }.run, .{&ctx});

    const client_stream = try std.net.tcpConnectToAddress(bound);
    defer client_stream.close();

    var net_read_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var net_write_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var net_reader = client_stream.reader(&net_read_buf);
    var net_writer = client_stream.writer(&net_write_buf);

    var client_read_buf: [4096]u8 = undefined;
    var client_write_buf: [4096]u8 = undefined;

    var tls_client = try tls.Client.init(net_reader.interface(), &net_writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &client_read_buf,
        .write_buffer = &client_write_buf,
    });

    const msg = "Hello, world!";
    try tls_client.writer.writeAll(msg);
    try tls_client.writer.flush();
    // std tls.Client's TLS-level flush only stages the encrypted record into
    // the underlying net writer's buffer; the caller must flush it to the
    // socket (std.http does the same when using tls.Client).
    try net_writer.interface.flush();

    var echo_buf: [msg.len]u8 = undefined;
    try tls_client.reader.readSliceAll(&echo_buf);
    try std.testing.expectEqualStrings(msg, &echo_buf);

    try tls_client.end();
    try net_writer.interface.flush();

    server_thread.join();
    try std.testing.expect(ctx.ok.load(.seq_cst));
}
