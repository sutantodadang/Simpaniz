//! ACME v2 (RFC 8555 / Let's Encrypt) client + renewal daemon for
//! `SIMPANIZ_TLS_ACME=<domain>` — zero-manual-setup TLS certificates.
//!
//! Zero external dependencies: JWS (ES256), the JWK thumbprint (RFC 7638),
//! the PKCS#10 CSR, and the account/domain key PEM files are all hand-rolled
//! here on top of `std.crypto`/`std.http.Client`/`std.json`, reusing
//! `tls_server.zig`'s PEM/DER reading helpers rather than duplicating them.
//!
//! ponytail: HTTP-01 challenge only (no DNS-01/TLS-ALPN-01 — HTTP-01 needs no
//! DNS API credentials, matching the "zero manual setup" goal). Single
//! domain per order (no SANs beyond the one hostname). No live ACME network
//! calls in the test suite — those tests cover the offline building blocks
//! (base64url, JWS sign+verify, JWK thumbprint, CSR build+parse, X.509
//! notAfter parsing, the HTTP-01 challenge responder) that the network flow
//! below is assembled from.
const std = @import("std");
const Allocator = std.mem.Allocator;
const tls_server = @import("tls_server.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const default_directory_url = "https://acme-v02.api.letsencrypt.org/directory";

/// Renew whenever the active certificate's notAfter is closer than this.
const renewal_window_s: i64 = 30 * 24 * 60 * 60;
/// Background renewal check cadence.
const renewal_check_interval_ns: u64 = 24 * 60 * 60 * std.time.ns_per_s;
/// Challenge/order poll cadence and attempt cap (~60s total).
const poll_interval_ns: u64 = 2 * std.time.ns_per_s;
const poll_max_attempts: usize = 30;

// ---------------------------------------------------------------------------
// Hot-swappable TLS cert/key pair.
// ---------------------------------------------------------------------------

/// Holds the `tls_server.ServerContext` the TLS accept path reads per
/// connection. When TLS is configured manually (`SIMPANIZ_TLS_CERT`/`_KEY`)
/// the pair is set once and never swapped. When ACME manages the
/// certificate, the renewal daemon calls `swap` after a successful reissue.
pub const TlsHolder = struct {
    mutex: std.Thread.Mutex = .{},
    ctx: *tls_server.ServerContext,

    pub fn current(self: *TlsHolder) *tls_server.ServerContext {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ctx;
    }

    /// Swaps in a newly issued cert/key pair. The previous `ServerContext` is
    /// intentionally leaked rather than freed: a connection may have grabbed
    /// the old pointer via `current()` just before the swap and could still
    /// be mid-handshake with it. ACME renewals are infrequent (roughly
    /// monthly) and each `ServerContext` is a tiny arena (one cert chain +
    /// one P-256 key), so leaking the outgoing one is far simpler and safer
    /// than refcounting every reader for a saving that doesn't matter at
    /// this cadence.
    pub fn swap(self: *TlsHolder, new_ctx: *tls_server.ServerContext) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ctx = new_ctx;
    }
};

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5, no padding) — used throughout JWS/JWK/CSR.
// ---------------------------------------------------------------------------

fn b64urlEncode(a: Allocator, bytes: []const u8) ![]u8 {
    const Enc = std.base64.url_safe_no_pad.Encoder;
    const out = try a.alloc(u8, Enc.calcSize(bytes.len));
    _ = Enc.encode(out, bytes);
    return out;
}

fn b64urlDecode(a: Allocator, s: []const u8) ![]u8 {
    const Dec = std.base64.url_safe_no_pad.Decoder;
    const out = try a.alloc(u8, try Dec.calcSizeForSlice(s));
    try Dec.decode(out, s);
    return out;
}

// ---------------------------------------------------------------------------
// JWK / RFC 7638 thumbprint.
// ---------------------------------------------------------------------------

/// Canonical JWK JSON for a P-256 key, member order per RFC 7638 §3
/// (lexicographic: crv, kty, x, y — already alphabetical here).
fn jwkJson(a: Allocator, key: Ecdsa.KeyPair) ![]u8 {
    const pt = key.public_key.toUncompressedSec1();
    const x_b64 = try b64urlEncode(a, pt[1..33]);
    defer a.free(x_b64);
    const y_b64 = try b64urlEncode(a, pt[33..65]);
    defer a.free(y_b64);
    return std.fmt.allocPrint(a, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 });
}

fn jwkThumbprint(a: Allocator, x_b64: []const u8, y_b64: []const u8) ![32]u8 {
    const json = try std.fmt.allocPrint(a, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 });
    defer a.free(json);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(json, &out, .{});
    return out;
}

/// `<token>.<base64url(SHA-256(JWK thumbprint JSON))>` (RFC 8555 §8.1).
fn buildKeyAuthorization(a: Allocator, account_key: Ecdsa.KeyPair, token: []const u8) ![]u8 {
    const pt = account_key.public_key.toUncompressedSec1();
    const x_b64 = try b64urlEncode(a, pt[1..33]);
    defer a.free(x_b64);
    const y_b64 = try b64urlEncode(a, pt[33..65]);
    defer a.free(y_b64);
    const thumb = try jwkThumbprint(a, x_b64, y_b64);
    const thumb_b64 = try b64urlEncode(a, &thumb);
    defer a.free(thumb_b64);
    return std.fmt.allocPrint(a, "{s}.{s}", .{ token, thumb_b64 });
}

// ---------------------------------------------------------------------------
// JWS (ES256, flattened JSON serialization).
// ---------------------------------------------------------------------------

const JwsParts = struct {
    protected_b64: []u8,
    payload_b64: []u8,
    signature_b64: []u8,

    fn deinit(self: JwsParts, a: Allocator) void {
        a.free(self.protected_b64);
        a.free(self.payload_b64);
        a.free(self.signature_b64);
    }
};

/// Signs `protected_json.payload_json` (both base64url-encoded first) with
/// `key`, using the raw 64-byte (r||s) ES256 signature encoding (RFC 7518
/// §3.4) — distinct from the DER encoding the CSR signature uses below.
fn signJws(a: Allocator, key: Ecdsa.KeyPair, protected_json: []const u8, payload_json: []const u8) !JwsParts {
    const protected_b64 = try b64urlEncode(a, protected_json);
    errdefer a.free(protected_b64);
    const payload_b64 = try b64urlEncode(a, payload_json);
    errdefer a.free(payload_b64);

    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ protected_b64, payload_b64 });
    defer a.free(signing_input);
    const sig = try key.sign(signing_input, null);
    const raw = sig.toBytes();
    const signature_b64 = try b64urlEncode(a, &raw);

    return .{ .protected_b64 = protected_b64, .payload_b64 = payload_b64, .signature_b64 = signature_b64 };
}

fn jwsBody(a: Allocator, parts: JwsParts) ![]u8 {
    return std.fmt.allocPrint(
        a,
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ parts.protected_b64, parts.payload_b64, parts.signature_b64 },
    );
}

// ---------------------------------------------------------------------------
// PEM encode (inverse of `tls_server.pemDecodeAll`).
// ---------------------------------------------------------------------------

fn pemEncode(a: Allocator, label: []const u8, der: []const u8) ![]u8 {
    const Enc = std.base64.standard.Encoder;
    const b64 = try a.alloc(u8, Enc.calcSize(der.len));
    defer a.free(b64);
    _ = Enc.encode(b64, der);

    var out = std.ArrayList(u8){};
    errdefer out.deinit(a);
    try out.appendSlice(a, "-----BEGIN ");
    try out.appendSlice(a, label);
    try out.appendSlice(a, "-----\n");
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        const end = @min(i + 64, b64.len);
        try out.appendSlice(a, b64[i..end]);
        try out.append(a, '\n');
    }
    try out.appendSlice(a, "-----END ");
    try out.appendSlice(a, label);
    try out.appendSlice(a, "-----\n");
    return out.toOwnedSlice(a);
}

// ---------------------------------------------------------------------------
// Minimal DER writer (SEQUENCE/SET/INTEGER/OID/BIT STRING/UTF8String/OCTET
// STRING/context tags) — just enough for a SEC1 EC private key and a
// PKCS#10 CSR with a subjectAltName extension request.
// ---------------------------------------------------------------------------

fn appendDerLen(a: Allocator, out: *std.ArrayList(u8), len: usize) !void {
    if (len < 0x80) {
        try out.append(a, @intCast(len));
        return;
    }
    var tmp: [8]u8 = undefined;
    var n: usize = 0;
    var v = len;
    while (v > 0) : (v >>= 8) {
        tmp[n] = @intCast(v & 0xff);
        n += 1;
    }
    try out.append(a, @intCast(0x80 | n));
    var i = n;
    while (i > 0) {
        i -= 1;
        try out.append(a, tmp[i]);
    }
}

fn derTlv(a: Allocator, tag: u8, content: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(a);
    try out.append(a, tag);
    try appendDerLen(a, &out, content.len);
    try out.appendSlice(a, content);
    return out.toOwnedSlice(a);
}

fn derWrap(a: Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var content = std.ArrayList(u8){};
    defer content.deinit(a);
    for (parts) |p| try content.appendSlice(a, p);
    return derTlv(a, tag, content.items);
}

fn derSeq(a: Allocator, parts: []const []const u8) ![]u8 {
    return derWrap(a, 0x30, parts);
}

fn intTlv(a: Allocator, v: u8) ![]u8 {
    return derTlv(a, 0x02, &[_]u8{v});
}

fn bitStringTlv(a: Allocator, bytes: []const u8) ![]u8 {
    const content = try a.alloc(u8, bytes.len + 1);
    defer a.free(content);
    content[0] = 0; // 0 unused bits
    @memcpy(content[1..], bytes);
    return derTlv(a, 0x03, content);
}

fn utf8Tlv(a: Allocator, s: []const u8) ![]u8 {
    return derTlv(a, 0x0C, s);
}

/// GeneralName `dNSName` — context class, primitive, tag 2 → 0x82.
fn dnsNameTlv(a: Allocator, s: []const u8) ![]u8 {
    return derTlv(a, 0x82, s);
}

fn encodeOid(a: Allocator, arcs: []const u32) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(a);
    try out.append(a, @intCast(arcs[0] * 40 + arcs[1]));
    for (arcs[2..]) |arc| {
        var buf: [5]u8 = undefined;
        var i: usize = 5;
        var v = arc;
        i -= 1;
        buf[i] = @intCast(v & 0x7f);
        v >>= 7;
        while (v > 0) {
            i -= 1;
            buf[i] = @intCast((v & 0x7f) | 0x80);
            v >>= 7;
        }
        try out.appendSlice(a, buf[i..]);
    }
    return out.toOwnedSlice(a);
}

fn oidTlv(a: Allocator, arcs: []const u32) ![]u8 {
    const content = try encodeOid(a, arcs);
    defer a.free(content);
    return derTlv(a, 0x06, content);
}

const oid_common_name = [_]u32{ 2, 5, 4, 3 };
const oid_ec_public_key = [_]u32{ 1, 2, 840, 10045, 2, 1 };
const oid_prime256v1 = [_]u32{ 1, 2, 840, 10045, 3, 1, 7 };
const oid_ecdsa_with_sha256 = [_]u32{ 1, 2, 840, 10045, 4, 3, 2 };
const oid_extension_request = [_]u32{ 1, 2, 840, 113549, 1, 9, 14 };
const oid_subject_alt_name = [_]u32{ 2, 5, 29, 17 };

/// Builds a PKCS#10 CertificationRequest DER for `domain`, signed by `key`
/// (which must be the key the caller wants the resulting certificate for):
/// subject CN=domain, subjectPublicKeyInfo = key's public point, an
/// extensionRequest attribute carrying subjectAltName dNSName=domain, signed
/// ecdsa-with-SHA256 (DER-encoded signature, per PKCS#10 — unlike the raw
/// r||s encoding JWS uses).
fn buildCsrDer(a: Allocator, domain: []const u8, key: Ecdsa.KeyPair) ![]u8 {
    // subject: SEQUENCE { SET { SEQUENCE { OID commonName, UTF8String domain } } }
    const cn_oid = try oidTlv(a, &oid_common_name);
    defer a.free(cn_oid);
    const cn_val = try utf8Tlv(a, domain);
    defer a.free(cn_val);
    const atv = try derSeq(a, &.{ cn_oid, cn_val });
    defer a.free(atv);
    const rdn = try derWrap(a, 0x31, &.{atv});
    defer a.free(rdn);
    const subject = try derSeq(a, &.{rdn});
    defer a.free(subject);

    // subjectPublicKeyInfo
    const alg_oid = try oidTlv(a, &oid_ec_public_key);
    defer a.free(alg_oid);
    const curve_oid = try oidTlv(a, &oid_prime256v1);
    defer a.free(curve_oid);
    const alg_id = try derSeq(a, &.{ alg_oid, curve_oid });
    defer a.free(alg_id);
    const pub_point = key.public_key.toUncompressedSec1();
    const pub_bits = try bitStringTlv(a, &pub_point);
    defer a.free(pub_bits);
    const spki = try derSeq(a, &.{ alg_id, pub_bits });
    defer a.free(spki);

    // attributes: [0] IMPLICIT SET OF Attribute, one extensionRequest
    // attribute carrying one Extensions SEQUENCE with one SAN extension.
    const dns = try dnsNameTlv(a, domain);
    defer a.free(dns);
    const gen_names = try derSeq(a, &.{dns}); // GeneralNames ::= SEQUENCE OF GeneralName
    defer a.free(gen_names);
    const san_oid = try oidTlv(a, &oid_subject_alt_name);
    defer a.free(san_oid);
    const san_octet = try derTlv(a, 0x04, gen_names);
    defer a.free(san_octet);
    const extension = try derSeq(a, &.{ san_oid, san_octet });
    defer a.free(extension);
    const extensions = try derSeq(a, &.{extension}); // Extensions ::= SEQUENCE OF Extension
    defer a.free(extensions);
    const ext_set = try derWrap(a, 0x31, &.{extensions}); // SET SIZE(1) OF Extensions
    defer a.free(ext_set);
    const ext_req_oid = try oidTlv(a, &oid_extension_request);
    defer a.free(ext_req_oid);
    const attribute = try derSeq(a, &.{ ext_req_oid, ext_set });
    defer a.free(attribute);
    const attributes = try derWrap(a, 0xA0, &.{attribute});
    defer a.free(attributes);

    const version = try intTlv(a, 0);
    defer a.free(version);
    const cri = try derSeq(a, &.{ version, subject, spki, attributes });
    defer a.free(cri);

    const sig = try key.sign(cri, null);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_buf);

    const sig_alg_oid = try oidTlv(a, &oid_ecdsa_with_sha256);
    defer a.free(sig_alg_oid);
    const sig_alg = try derSeq(a, &.{sig_alg_oid});
    defer a.free(sig_alg);
    const sig_bits = try bitStringTlv(a, der_sig);
    defer a.free(sig_bits);

    return derSeq(a, &.{ cri, sig_alg, sig_bits });
}

// ---------------------------------------------------------------------------
// Minimal DER TLV reader for the CSR parser (test-only consumer). Mirrors
// `tls_server.zig`'s `readTlv` in spirit but kept local since it walks a
// different (CSR) schema.
// ---------------------------------------------------------------------------

const Tlv = struct { tag: u8, content: []const u8, next: usize };

fn readTlv(buf: []const u8, pos: usize) error{BadDer}!Tlv {
    if (pos + 2 > buf.len) return error.BadDer;
    const tag = buf[pos];
    const len_byte = buf[pos + 1];
    var idx = pos + 2;
    var len: usize = undefined;
    if (len_byte & 0x80 == 0) {
        len = len_byte;
    } else {
        const nbytes = len_byte & 0x7f;
        if (nbytes == 0 or nbytes > 4 or idx + nbytes > buf.len) return error.BadDer;
        len = 0;
        for (0..nbytes) |i| len = (len << 8) | buf[idx + i];
        idx += nbytes;
    }
    if (idx + len > buf.len) return error.BadDer;
    return .{ .tag = tag, .content = buf[idx..][0..len], .next = idx + len };
}

const ParsedCsr = struct {
    /// Raw DER bytes of certificationRequestInfo (the signed portion).
    tbs: []const u8,
    version_zero: bool,
    cn: []const u8,
    san_dns: []const u8,
    signature: Ecdsa.Signature,
};

fn parseCsrDer(der: []const u8) !ParsedCsr {
    const outer = try readTlv(der, 0);
    if (outer.tag != 0x30) return error.BadCsr;
    const oc = outer.content;

    const cri_tlv = try readTlv(oc, 0);
    if (cri_tlv.tag != 0x30) return error.BadCsr;
    const tbs = oc[0..cri_tlv.next];

    const sig_alg_tlv = try readTlv(oc, cri_tlv.next);
    if (sig_alg_tlv.tag != 0x30) return error.BadCsr;

    const sig_bits_tlv = try readTlv(oc, sig_alg_tlv.next);
    if (sig_bits_tlv.tag != 0x03) return error.BadCsr;
    if (sig_bits_tlv.content.len < 1 or sig_bits_tlv.content[0] != 0) return error.BadCsr;
    const signature = Ecdsa.Signature.fromDer(sig_bits_tlv.content[1..]) catch return error.BadCsr;

    const cric = cri_tlv.content;
    const version_tlv = try readTlv(cric, 0);
    if (version_tlv.tag != 0x02) return error.BadCsr;
    const version_zero = version_tlv.content.len == 1 and version_tlv.content[0] == 0;

    const subject_tlv = try readTlv(cric, version_tlv.next);
    if (subject_tlv.tag != 0x30) return error.BadCsr;
    const rdn_tlv = try readTlv(subject_tlv.content, 0);
    if (rdn_tlv.tag != 0x31) return error.BadCsr;
    const atv_tlv = try readTlv(rdn_tlv.content, 0);
    if (atv_tlv.tag != 0x30) return error.BadCsr;
    const cn_oid_tlv = try readTlv(atv_tlv.content, 0);
    if (cn_oid_tlv.tag != 0x06) return error.BadCsr;
    const cn_val_tlv = try readTlv(atv_tlv.content, cn_oid_tlv.next);
    if (cn_val_tlv.tag != 0x0C) return error.BadCsr;
    const cn = cn_val_tlv.content;

    const spki_tlv = try readTlv(cric, subject_tlv.next);
    if (spki_tlv.tag != 0x30) return error.BadCsr;

    const attrs_tlv = try readTlv(cric, spki_tlv.next);
    if (attrs_tlv.tag != 0xA0) return error.BadCsr;
    const attribute_tlv = try readTlv(attrs_tlv.content, 0);
    if (attribute_tlv.tag != 0x30) return error.BadCsr;
    const attr_oid_tlv = try readTlv(attribute_tlv.content, 0);
    if (attr_oid_tlv.tag != 0x06) return error.BadCsr;
    const attr_set_tlv = try readTlv(attribute_tlv.content, attr_oid_tlv.next);
    if (attr_set_tlv.tag != 0x31) return error.BadCsr;
    const extensions_tlv = try readTlv(attr_set_tlv.content, 0);
    if (extensions_tlv.tag != 0x30) return error.BadCsr;
    const extension_tlv = try readTlv(extensions_tlv.content, 0);
    if (extension_tlv.tag != 0x30) return error.BadCsr;
    const ext_oid_tlv = try readTlv(extension_tlv.content, 0);
    if (ext_oid_tlv.tag != 0x06) return error.BadCsr;
    const ext_val_tlv = try readTlv(extension_tlv.content, ext_oid_tlv.next);
    if (ext_val_tlv.tag != 0x04) return error.BadCsr;
    const gen_names_tlv = try readTlv(ext_val_tlv.content, 0);
    if (gen_names_tlv.tag != 0x30) return error.BadCsr;
    const dns_tlv = try readTlv(gen_names_tlv.content, 0);
    if (dns_tlv.tag != 0x82) return error.BadCsr;

    return .{ .tbs = tbs, .version_zero = version_zero, .cn = cn, .san_dns = dns_tlv.content, .signature = signature };
}

// ---------------------------------------------------------------------------
// X.509 notAfter — reuses `std.crypto.Certificate.parse` (already used by
// `tls_server.ServerContext.load`) plus `tls_server.pemDecodeAll`, rather
// than re-deriving an ASN.1 UTCTime/GeneralizedTime walker that already
// exists and is exercised by the TLS handshake path.
// ---------------------------------------------------------------------------

fn certNotAfterEpoch(a: Allocator, pem: []const u8) !i64 {
    const blocks = try tls_server.pemDecodeAll(a, pem);
    defer {
        for (blocks) |b| a.free(b.der);
        a.free(blocks);
    }
    for (blocks) |b| {
        if (!std.mem.eql(u8, b.label, "CERTIFICATE")) continue;
        const cert: std.crypto.Certificate = .{ .buffer = b.der, .index = 0 };
        const parsed = try cert.parse();
        return @intCast(parsed.validity.not_after);
    }
    return error.NoCertificatesFound;
}

// ---------------------------------------------------------------------------
// Key persistence: account_key.pem / domain_key.pem, minimal SEC1 DER
// (SEQUENCE { INTEGER 1, OCTET STRING privateKey(32) }) — the optional SEC1
// `parameters`/`publicKey` fields are omitted; `tls_server.extractP256Scalar`
// only needs the version + private-key OCTET STRING to read a key back.
// ---------------------------------------------------------------------------

fn writeKeyPem(gpa: Allocator, dir: std.fs.Dir, filename: []const u8, kp: Ecdsa.KeyPair) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const version = try intTlv(a, 1);
    const scalar_bytes = kp.secret_key.toBytes();
    const priv = try derTlv(a, 0x04, &scalar_bytes);
    const der = try derSeq(a, &.{ version, priv });
    const pem = try pemEncode(a, "EC PRIVATE KEY", der);
    try dir.writeFile(.{ .sub_path = filename, .data = pem });
}

fn loadKeyPem(gpa: Allocator, pem: []const u8) !Ecdsa.KeyPair {
    const blocks = try tls_server.pemDecodeAll(gpa, pem);
    defer {
        for (blocks) |b| gpa.free(b.der);
        gpa.free(blocks);
    }
    if (blocks.len == 0) return error.NoKeyFound;
    const scalar = try tls_server.extractP256Scalar(blocks[0].der);
    const sk = try Ecdsa.SecretKey.fromBytes(scalar);
    return Ecdsa.KeyPair.fromSecretKey(sk);
}

/// Loads `<dir>/<filename>` if present, else generates a fresh P-256 key
/// pair and persists it (so the account identity — and, for the domain key,
/// nothing load-bearing, but consistent — survives restarts).
fn ensureKeyFile(gpa: Allocator, dir: std.fs.Dir, filename: []const u8) !Ecdsa.KeyPair {
    const pem = dir.readFileAlloc(gpa, filename, 1 << 16) catch |err| switch (err) {
        error.FileNotFound => {
            const kp = Ecdsa.KeyPair.generate();
            try writeKeyPem(gpa, dir, filename, kp);
            return kp;
        },
        else => return err,
    };
    defer gpa.free(pem);
    return loadKeyPem(gpa, pem);
}

// ---------------------------------------------------------------------------
// HTTP-01 challenge responder: minimal ephemeral HTTP/1.1 listener that only
// answers `GET /.well-known/acme-challenge/<token>`.
// ---------------------------------------------------------------------------

const ChallengeServer = struct {
    listener: std.net.Server,
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = .init(true),
    token: []const u8,
    key_authorization: []const u8,

    fn start(gpa: Allocator, port: u16, token: []const u8, key_authorization: []const u8) !*ChallengeServer {
        const self = try gpa.create(ChallengeServer);
        errdefer gpa.destroy(self);
        const addr = try std.net.Address.parseIp("0.0.0.0", port);
        self.* = .{
            .listener = try addr.listen(.{ .reuse_address = true }),
            .token = token,
            .key_authorization = key_authorization,
        };
        self.thread = std.Thread.spawn(.{}, run, .{self}) catch |err| {
            self.listener.deinit();
            gpa.destroy(self);
            return err;
        };
        return self;
    }

    fn stop(self: *ChallengeServer, gpa: Allocator) void {
        self.running.store(false, .seq_cst);
        // Unblock a pending accept() with a dummy local connection. Connect
        // to loopback rather than the (possibly wildcard 0.0.0.0) bound
        // address — some platforms (Windows) reject connecting to 0.0.0.0.
        if (std.net.Address.parseIp("127.0.0.1", self.listener.listen_address.getPort())) |addr| {
            if (std.net.tcpConnectToAddress(addr)) |s| {
                s.close();
            } else |_| {}
        } else |_| {}
        if (self.thread) |t| t.join();
        self.listener.deinit();
        gpa.destroy(self);
    }

    fn run(self: *ChallengeServer) void {
        while (self.running.load(.seq_cst)) {
            const conn = self.listener.accept() catch |e| {
                if (!self.running.load(.seq_cst)) return;
                std.log.warn("acme http-01: accept failed: {}", .{e});
                continue;
            };
            self.handleOne(conn.stream);
        }
    }

    fn handleOne(self: *ChallengeServer, stream: std.net.Stream) void {
        defer stream.close();
        if (!self.running.load(.seq_cst)) return;

        // `stream.read`/`writeAll` (the plain POSIX-style wrappers) are
        // deprecated in favor of the buffered `Io.Reader`/`Io.Writer`
        // interface — use that instead, matching `server.zig`'s connection
        // handling.
        var read_buf: [2048]u8 = undefined;
        var sr = stream.reader(&read_buf);
        const input = sr.interface();
        input.fillMore() catch return;
        const req = input.buffered();
        if (req.len == 0) return;

        const line_end = std.mem.indexOf(u8, req, "\r\n") orelse req.len;
        const line = req[0..line_end];
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const method = it.next() orelse return;
        const path = it.next() orelse return;

        var write_buf: [2048]u8 = undefined;
        var sw = stream.writer(&write_buf);
        const output = &sw.interface;

        const prefix = "/.well-known/acme-challenge/";
        if (std.mem.eql(u8, method, "GET") and std.mem.startsWith(u8, path, prefix) and
            std.mem.eql(u8, path[prefix.len..], self.token))
        {
            const body = self.key_authorization;
            output.print(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                .{ body.len, body },
            ) catch return;
        } else {
            output.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch return;
        }
        output.flush() catch return;
    }
};

// ---------------------------------------------------------------------------
// HTTP transport: a thin wrapper around `std.http.Client` that (unlike
// `Client.fetch`, which only surfaces the status code) also hands back the
// `Replay-Nonce`/`Location` response headers ACME needs on every call.
// ---------------------------------------------------------------------------

const HttpResult = struct {
    status: std.http.Status,
    body: []u8,
    nonce: ?[]u8,
    location: ?[]u8,
};

fn httpRequest(
    a: Allocator,
    client: *std.http.Client,
    method: std.http.Method,
    url: []const u8,
    content_type: ?[]const u8,
    payload: ?[]const u8,
) !HttpResult {
    const uri = try std.Uri.parse(url);

    var headers_buf: [1]std.http.Header = undefined;
    var extra_headers: []const std.http.Header = &.{};
    if (content_type) |ct| {
        headers_buf[0] = .{ .name = "Content-Type", .value = ct };
        extra_headers = headers_buf[0..1];
    }

    var req = try client.request(method, uri, .{
        .keep_alive = false,
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    if (payload) |p| {
        const buf = try a.dupe(u8, p);
        try req.sendBodyComplete(buf);
    } else {
        try req.sendBodiless();
    }

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    // Must be read before `response.reader()`, which invalidates `head`'s
    // borrowed strings.
    var nonce: ?[]u8 = null;
    var it = response.head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "replay-nonce")) {
            nonce = try a.dupe(u8, h.value);
        }
    }
    const location: ?[]u8 = if (response.head.location) |l| try a.dupe(u8, l) else null;
    const status = response.head.status;

    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .zstd => try a.alloc(u8, std.compress.zstd.default_window_len),
        .deflate, .gzip => try a.alloc(u8, std.compress.flate.max_window_len),
        .compress => return error.UnsupportedCompressionMethod,
    };
    defer if (decompress_buffer.len > 0) a.free(decompress_buffer);

    var transfer_buf: [1024]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buf, &decompress, decompress_buffer);

    var body_aw: std.Io.Writer.Allocating = .init(a);
    _ = reader.streamRemaining(&body_aw.writer) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        else => |e| return e,
    };

    return .{ .status = status, .body = try body_aw.toOwnedSlice(), .nonce = nonce, .location = location };
}

// ---------------------------------------------------------------------------
// JSON helpers (mirrors `sts.zig`'s `getStr`/`getInt` idiom for
// `std.json.Value`).
// ---------------------------------------------------------------------------

fn getStr(doc: std.json.Value, field: []const u8) ?[]const u8 {
    if (doc != .object) return null;
    const v = doc.object.get(field) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn isBadNonceError(body: []const u8) bool {
    return std.mem.indexOf(u8, body, "badNonce") != null;
}

// ---------------------------------------------------------------------------
// ACME v2 flow (RFC 8555). No test exercises this end-to-end (it needs a
// live ACME server) — it's assembled from the offline-tested building blocks
// above.
// ---------------------------------------------------------------------------

fn buildProtectedHeader(a: Allocator, nonce: []const u8, url: []const u8, kid: ?[]const u8, jwk_json: ?[]const u8) ![]u8 {
    if (kid) |k| {
        return std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"nonce\":\"{s}\",\"url\":\"{s}\",\"kid\":\"{s}\"}}", .{ nonce, url, k });
    }
    return std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"nonce\":\"{s}\",\"url\":\"{s}\",\"jwk\":{s}}}", .{ nonce, url, jwk_json.? });
}

fn signedPost(
    a: Allocator,
    client: *std.http.Client,
    key: Ecdsa.KeyPair,
    url: []const u8,
    payload_json: []const u8,
    nonce: []const u8,
    kid: ?[]const u8,
) !HttpResult {
    const jwk: ?[]const u8 = if (kid == null) try jwkJson(a, key) else null;
    const protected = try buildProtectedHeader(a, nonce, url, kid, jwk);
    const parts = try signJws(a, key, protected, payload_json);
    const body = try jwsBody(a, parts);
    return httpRequest(a, client, .POST, url, "application/jose+json", body);
}

/// Signed POST (or POST-as-GET, when `payload_json` is `""`) with one retry
/// on `badNonce` using the fresh nonce the error response carries. Returns
/// gpa-owned `body`/`location`; updates `*nonce` in place for the next call.
fn signedRequest(
    gpa: Allocator,
    client: *std.http.Client,
    key: Ecdsa.KeyPair,
    url: []const u8,
    payload_json: []const u8,
    kid: ?[]const u8,
    nonce: *[]u8,
) !struct { status: std.http.Status, body: []u8, location: ?[]u8 } {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const s = arena.allocator();

        const res = try signedPost(s, client, key, url, payload_json, nonce.*, kid);

        if (res.nonce) |n| {
            const new_nonce = try gpa.dupe(u8, n);
            gpa.free(nonce.*);
            nonce.* = new_nonce;
        }

        if (@intFromEnum(res.status) == 400 and attempt == 0 and isBadNonceError(res.body)) continue;

        const body_owned = try gpa.dupe(u8, res.body);
        const loc_owned: ?[]u8 = if (res.location) |l| try gpa.dupe(u8, l) else null;
        return .{ .status = res.status, .body = body_owned, .location = loc_owned };
    }
}

const Directory = struct {
    new_nonce: []u8,
    new_account: []u8,
    new_order: []u8,

    fn deinit(self: Directory, gpa: Allocator) void {
        gpa.free(self.new_nonce);
        gpa.free(self.new_account);
        gpa.free(self.new_order);
    }
};

fn fetchDirectory(gpa: Allocator, client: *std.http.Client, url: []const u8) !Directory {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const s = arena.allocator();

    const res = try httpRequest(s, client, .GET, url, null, null);
    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) return error.DirectoryFetchFailed;

    const doc = std.json.parseFromSliceLeaky(std.json.Value, s, res.body, .{}) catch return error.DirectoryParseFailed;
    const new_nonce = getStr(doc, "newNonce") orelse return error.DirectoryParseFailed;
    const new_account = getStr(doc, "newAccount") orelse return error.DirectoryParseFailed;
    const new_order = getStr(doc, "newOrder") orelse return error.DirectoryParseFailed;

    return .{
        .new_nonce = try gpa.dupe(u8, new_nonce),
        .new_account = try gpa.dupe(u8, new_account),
        .new_order = try gpa.dupe(u8, new_order),
    };
}

fn getNonce(gpa: Allocator, client: *std.http.Client, new_nonce_url: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const s = arena.allocator();

    const res = try httpRequest(s, client, .HEAD, new_nonce_url, null, null);
    const nonce = res.nonce orelse return error.NonceFetchFailed;
    return gpa.dupe(u8, nonce);
}

fn ensureAccount(
    gpa: Allocator,
    client: *std.http.Client,
    key: Ecdsa.KeyPair,
    new_account_url: []const u8,
    contact: ?[]const u8,
    nonce: *[]u8,
) ![]u8 {
    const payload = blk: {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const s = arena.allocator();
        const p = if (contact) |c|
            try std.fmt.allocPrint(s, "{{\"termsOfServiceAgreed\":true,\"contact\":[\"{s}\"]}}", .{c})
        else
            try std.fmt.allocPrint(s, "{{\"termsOfServiceAgreed\":true}}", .{});
        break :blk try gpa.dupe(u8, p);
    };
    defer gpa.free(payload);

    const res = try signedRequest(gpa, client, key, new_account_url, payload, null, nonce);
    defer gpa.free(res.body);
    errdefer if (res.location) |l| gpa.free(l);

    const code = @intFromEnum(res.status);
    if (code != 200 and code != 201) {
        std.log.err("acme: newAccount failed status={d} body={s}", .{ code, res.body });
        if (res.location) |l| gpa.free(l);
        return error.AccountFailed;
    }
    return res.location orelse return error.AccountFailed;
}

const Order = struct {
    self_url: []u8,
    finalize: []u8,
    authorizations: [][]u8,

    fn deinit(self: Order, gpa: Allocator) void {
        gpa.free(self.self_url);
        gpa.free(self.finalize);
        for (self.authorizations) |a| gpa.free(a);
        gpa.free(self.authorizations);
    }
};

fn createOrder(
    gpa: Allocator,
    client: *std.http.Client,
    key: Ecdsa.KeyPair,
    new_order_url: []const u8,
    domain: []const u8,
    kid: []const u8,
    nonce: *[]u8,
) !Order {
    const payload = try std.fmt.allocPrint(gpa, "{{\"identifiers\":[{{\"type\":\"dns\",\"value\":\"{s}\"}}]}}", .{domain});
    defer gpa.free(payload);

    const res = try signedRequest(gpa, client, key, new_order_url, payload, kid, nonce);
    defer gpa.free(res.body);
    defer if (res.location) |l| gpa.free(l);

    const code = @intFromEnum(res.status);
    if (code != 200 and code != 201) {
        std.log.err("acme: newOrder failed status={d} body={s}", .{ code, res.body });
        return error.OrderFailed;
    }
    const loc = res.location orelse return error.OrderFailed;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const s = arena.allocator();
    const doc = std.json.parseFromSliceLeaky(std.json.Value, s, res.body, .{}) catch return error.OrderFailed;
    const finalize = getStr(doc, "finalize") orelse return error.OrderFailed;
    if (doc != .object) return error.OrderFailed;
    const auths_v = doc.object.get("authorizations") orelse return error.OrderFailed;
    if (auths_v != .array) return error.OrderFailed;

    var auths = try gpa.alloc([]u8, auths_v.array.items.len);
    errdefer gpa.free(auths);
    var filled: usize = 0;
    errdefer for (auths[0..filled]) |a| gpa.free(a);
    for (auths_v.array.items) |item| {
        if (item != .string) return error.OrderFailed;
        auths[filled] = try gpa.dupe(u8, item.string);
        filled += 1;
    }

    return .{
        .self_url = try gpa.dupe(u8, loc),
        .finalize = try gpa.dupe(u8, finalize),
        .authorizations = auths,
    };
}

const Http01Challenge = struct { url: []u8, token: []u8 };
const Authorization = struct {
    status: []u8,
    http01: ?Http01Challenge,

    fn deinit(self: Authorization, gpa: Allocator) void {
        gpa.free(self.status);
        if (self.http01) |h| {
            gpa.free(h.url);
            gpa.free(h.token);
        }
    }
};

fn fetchAuthorization(
    gpa: Allocator,
    client: *std.http.Client,
    key: Ecdsa.KeyPair,
    url: []const u8,
    kid: []const u8,
    nonce: *[]u8,
) !Authorization {
    const res = try signedRequest(gpa, client, key, url, "", kid, nonce);
    defer gpa.free(res.body);
    defer if (res.location) |l| gpa.free(l);

    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) {
        std.log.err("acme: fetch authorization failed status={d} body={s}", .{ code, res.body });
        return error.AuthorizationFailed;
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const s = arena.allocator();
    const doc = std.json.parseFromSliceLeaky(std.json.Value, s, res.body, .{}) catch return error.AuthorizationFailed;
    const status = getStr(doc, "status") orelse return error.AuthorizationFailed;

    var http01: ?Http01Challenge = null;
    if (doc == .object) {
        if (doc.object.get("challenges")) |chs| {
            if (chs == .array) {
                for (chs.array.items) |c| {
                    if (c != .object) continue;
                    const ctype = getStr(c, "type") orelse continue;
                    if (!std.mem.eql(u8, ctype, "http-01")) continue;
                    const curl = getStr(c, "url") orelse continue;
                    const ctoken = getStr(c, "token") orelse continue;
                    http01 = .{ .url = try gpa.dupe(u8, curl), .token = try gpa.dupe(u8, ctoken) };
                    break;
                }
            }
        }
    }

    return .{ .status = try gpa.dupe(u8, status), .http01 = http01 };
}

fn respondToChallenge(gpa: Allocator, client: *std.http.Client, key: Ecdsa.KeyPair, challenge_url: []const u8, kid: []const u8, nonce: *[]u8) !void {
    const res = try signedRequest(gpa, client, key, challenge_url, "{}", kid, nonce);
    defer gpa.free(res.body);
    defer if (res.location) |l| gpa.free(l);
    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) {
        std.log.err("acme: challenge respond failed status={d} body={s}", .{ code, res.body });
        return error.ChallengeFailed;
    }
}

fn pollAuthorization(gpa: Allocator, client: *std.http.Client, key: Ecdsa.KeyPair, url: []const u8, kid: []const u8, nonce: *[]u8) !void {
    var i: usize = 0;
    while (i < poll_max_attempts) : (i += 1) {
        const authz = try fetchAuthorization(gpa, client, key, url, kid, nonce);
        defer authz.deinit(gpa);
        if (std.mem.eql(u8, authz.status, "valid")) return;
        if (std.mem.eql(u8, authz.status, "invalid")) return error.AuthorizationInvalid;
        std.Thread.sleep(poll_interval_ns);
    }
    return error.ChallengeTimeout;
}

fn finalizeOrder(gpa: Allocator, client: *std.http.Client, key: Ecdsa.KeyPair, finalize_url: []const u8, csr_b64: []const u8, kid: []const u8, nonce: *[]u8) !void {
    const payload = try std.fmt.allocPrint(gpa, "{{\"csr\":\"{s}\"}}", .{csr_b64});
    defer gpa.free(payload);

    const res = try signedRequest(gpa, client, key, finalize_url, payload, kid, nonce);
    defer gpa.free(res.body);
    defer if (res.location) |l| gpa.free(l);
    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) {
        std.log.err("acme: finalize failed status={d} body={s}", .{ code, res.body });
        return error.FinalizeFailed;
    }
}

fn pollOrderForCertUrl(gpa: Allocator, client: *std.http.Client, key: Ecdsa.KeyPair, order_url: []const u8, kid: []const u8, nonce: *[]u8) ![]u8 {
    var i: usize = 0;
    while (i < poll_max_attempts) : (i += 1) {
        const res = try signedRequest(gpa, client, key, order_url, "", kid, nonce);
        defer gpa.free(res.body);
        defer if (res.location) |l| gpa.free(l);

        const code = @intFromEnum(res.status);
        if (code < 200 or code >= 300) {
            std.log.err("acme: poll order failed status={d} body={s}", .{ code, res.body });
            return error.OrderFailed;
        }

        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const s = arena.allocator();
        const doc = std.json.parseFromSliceLeaky(std.json.Value, s, res.body, .{}) catch return error.OrderFailed;
        const status = getStr(doc, "status") orelse return error.OrderFailed;
        if (std.mem.eql(u8, status, "valid")) {
            const cert_url = getStr(doc, "certificate") orelse return error.OrderFailed;
            return gpa.dupe(u8, cert_url);
        }
        if (std.mem.eql(u8, status, "invalid")) return error.OrderInvalid;
        std.Thread.sleep(poll_interval_ns);
    }
    return error.ChallengeTimeout;
}

fn downloadCertificate(gpa: Allocator, client: *std.http.Client, key: Ecdsa.KeyPair, cert_url: []const u8, kid: []const u8, nonce: *[]u8) ![]u8 {
    const res = try signedRequest(gpa, client, key, cert_url, "", kid, nonce);
    defer if (res.location) |l| gpa.free(l);
    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) {
        gpa.free(res.body);
        return error.CertificateDownloadFailed;
    }
    return res.body;
}

/// Runs the full RFC 8555 issuance flow for `domain` and writes
/// `domain_key.pem`/`cert.pem` into `state_dir` on success.
fn issueCertificate(gpa: Allocator, state_dir: std.fs.Dir, domain: []const u8, directory_url: []const u8, contact: ?[]const u8, http_port: u16) !void {
    var client = std.http.Client{ .allocator = gpa };
    defer client.deinit();

    const account_key = try ensureKeyFile(gpa, state_dir, "account_key.pem");
    const domain_key = Ecdsa.KeyPair.generate();

    const dir = try fetchDirectory(gpa, &client, directory_url);
    defer dir.deinit(gpa);

    var nonce = try getNonce(gpa, &client, dir.new_nonce);
    defer gpa.free(nonce);

    const kid = try ensureAccount(gpa, &client, account_key, dir.new_account, contact, &nonce);
    defer gpa.free(kid);

    const order = try createOrder(gpa, &client, account_key, dir.new_order, domain, kid, &nonce);
    defer order.deinit(gpa);

    if (order.authorizations.len == 0) return error.NoAuthorizations;
    const authz_url = order.authorizations[0];

    const authz = try fetchAuthorization(gpa, &client, account_key, authz_url, kid, &nonce);
    var authz_done = false;
    defer if (!authz_done) authz.deinit(gpa);

    if (!std.mem.eql(u8, authz.status, "valid")) {
        const chal = authz.http01 orelse return error.NoHttp01Challenge;

        const key_auth = try buildKeyAuthorization(gpa, account_key, chal.token);
        defer gpa.free(key_auth);

        const srv = try ChallengeServer.start(gpa, http_port, chal.token, key_auth);
        defer srv.stop(gpa);

        try respondToChallenge(gpa, &client, account_key, chal.url, kid, &nonce);
        try pollAuthorization(gpa, &client, account_key, authz_url, kid, &nonce);
    }
    authz.deinit(gpa);
    authz_done = true;

    const csr_der = try buildCsrDer(gpa, domain, domain_key);
    defer gpa.free(csr_der);
    const csr_b64 = try b64urlEncode(gpa, csr_der);
    defer gpa.free(csr_b64);

    try finalizeOrder(gpa, &client, account_key, order.finalize, csr_b64, kid, &nonce);

    const cert_url = try pollOrderForCertUrl(gpa, &client, account_key, order.self_url, kid, &nonce);
    defer gpa.free(cert_url);

    const cert_pem = try downloadCertificate(gpa, &client, account_key, cert_url, kid, &nonce);
    defer gpa.free(cert_pem);

    try writeKeyPem(gpa, state_dir, "domain_key.pem", domain_key);
    try state_dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });

    std.log.info("acme: certificate issued for {s}", .{domain});
}

// ---------------------------------------------------------------------------
// State dir + boot-time / renewal entry points.
// ---------------------------------------------------------------------------

pub const CertPaths = struct { cert_path: []u8, key_path: []u8 };

/// Creates (if needed) and opens `<data_dir>/.simpaniz-acme`.
pub fn openOrCreateStateDir(data_dir: std.fs.Dir) !std.fs.Dir {
    data_dir.makeDir(".simpaniz-acme") catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    return data_dir.openDir(".simpaniz-acme", .{});
}

/// Builds the file paths `tls_server.ServerContext.load` should read,
/// relative to `data_dir_path` (the same string `SIMPANIZ_DATA_DIR` resolves
/// to — absolute or relative both work, matching how manually-configured
/// `SIMPANIZ_TLS_CERT`/`_KEY` paths are already read).
pub fn statePaths(gpa: Allocator, data_dir_path: []const u8) !CertPaths {
    return .{
        .cert_path = try std.fs.path.join(gpa, &.{ data_dir_path, ".simpaniz-acme", "cert.pem" }),
        .key_path = try std.fs.path.join(gpa, &.{ data_dir_path, ".simpaniz-acme", "domain_key.pem" }),
    };
}

fn needsIssuance(gpa: Allocator, state_dir: std.fs.Dir) bool {
    const pem = state_dir.readFileAlloc(gpa, "cert.pem", 1 << 20) catch return true;
    defer gpa.free(pem);
    const not_after = certNotAfterEpoch(gpa, pem) catch return true;
    const now = std.time.timestamp();
    return (not_after - now) < renewal_window_s;
}

/// Boot-time entry point: issues a certificate into `<data_dir>/.simpaniz-acme`
/// if none exists yet or the existing one expires within the renewal window;
/// otherwise a no-op. Runs synchronously — the TLS listener should not start
/// until this returns successfully.
pub fn ensureCertificate(gpa: Allocator, data_dir: std.fs.Dir, domain: []const u8, directory_url: []const u8, contact: ?[]const u8, http_port: u16) !void {
    var state_dir = try openOrCreateStateDir(data_dir);
    defer state_dir.close();

    if (needsIssuance(gpa, state_dir)) {
        std.log.info("acme: issuing certificate for {s} via {s}", .{ domain, directory_url });
        try issueCertificate(gpa, state_dir, domain, directory_url, contact, http_port);
    } else {
        std.log.info("acme: existing certificate for {s} still valid (> {d}d)", .{ domain, @divTrunc(renewal_window_s, 86400) });
    }
}

/// Background renewal daemon context. Owns a long-lived handle on the ACME
/// state dir and the swappable TLS holder to hot-swap into on success.
pub const RenewalCtx = struct {
    gpa: Allocator,
    state_dir: std.fs.Dir,
    cert_path: []const u8,
    key_path: []const u8,
    domain: []const u8,
    directory_url: []const u8,
    contact: ?[]const u8,
    http_port: u16,
    holder: *TlsHolder,
};

pub fn startRenewalDaemon(ctx: *RenewalCtx) !void {
    const t = try std.Thread.spawn(.{}, renewalLoop, .{ctx});
    t.detach();
}

fn renewalLoop(ctx: *RenewalCtx) void {
    while (true) {
        std.Thread.sleep(renewal_check_interval_ns);
        if (!needsIssuance(ctx.gpa, ctx.state_dir)) continue;

        std.log.info("acme: renewing certificate for {s}", .{ctx.domain});
        issueCertificate(ctx.gpa, ctx.state_dir, ctx.domain, ctx.directory_url, ctx.contact, ctx.http_port) catch |e| {
            std.log.err("acme: renewal failed, will retry next cycle (serving on current cert): {}", .{e});
            continue;
        };

        const new_ctx = tls_server.ServerContext.load(ctx.gpa, ctx.cert_path, ctx.key_path) catch |e| {
            std.log.err("acme: failed to reload renewed cert/key: {}", .{e});
            continue;
        };
        ctx.holder.swap(new_ctx);
        std.log.info("acme: certificate renewed and hot-swapped for {s}", .{ctx.domain});
    }
}

// ---------------------------------------------------------------------------
// Tests — all offline (no live ACME network calls).
// ---------------------------------------------------------------------------

test "acme: base64url encode/decode RFC 4648 vectors" {
    const gpa = std.testing.allocator;
    const vectors = [_][2][]const u8{
        .{ "", "" },
        .{ "f", "Zg" },
        .{ "fo", "Zm8" },
        .{ "foo", "Zm9v" },
        .{ "foobar", "Zm9vYmFy" },
    };
    for (vectors) |v| {
        const enc = try b64urlEncode(gpa, v[0]);
        defer gpa.free(enc);
        try std.testing.expectEqualStrings(v[1], enc);

        const dec = try b64urlDecode(gpa, v[1]);
        defer gpa.free(dec);
        try std.testing.expectEqualStrings(v[0], dec);
    }
}

test "acme: JWS sign+verify roundtrip" {
    const gpa = std.testing.allocator;
    const kp = Ecdsa.KeyPair.generate();

    const protected = "{\"alg\":\"ES256\",\"nonce\":\"test-nonce\",\"url\":\"https://example.com/acme/new-order\"}";
    const payload = "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.com\"}]}";

    const parts = try signJws(gpa, kp, protected, payload);
    defer parts.deinit(gpa);

    // Verify the signature over the exact `protected.payload` signing input.
    const signing_input = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ parts.protected_b64, parts.payload_b64 });
    defer gpa.free(signing_input);
    const sig_raw = try b64urlDecode(gpa, parts.signature_b64);
    defer gpa.free(sig_raw);
    try std.testing.expectEqual(@as(usize, 64), sig_raw.len);
    var raw64: [64]u8 = undefined;
    @memcpy(&raw64, sig_raw);
    const sig = Ecdsa.Signature.fromBytes(raw64);
    try sig.verify(signing_input, kp.public_key);

    // Round-trip protected/payload back to the original JSON.
    const protected_dec = try b64urlDecode(gpa, parts.protected_b64);
    defer gpa.free(protected_dec);
    try std.testing.expectEqualStrings(protected, protected_dec);
    const payload_dec = try b64urlDecode(gpa, parts.payload_b64);
    defer gpa.free(payload_dec);
    try std.testing.expectEqualStrings(payload, payload_dec);

    const body = try jwsBody(gpa, parts);
    defer gpa.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"protected\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"signature\":\"") != null);
}

test "acme: JWK thumbprint known-answer (RFC 7638 canonical form)" {
    const gpa = std.testing.allocator;
    const kp = Ecdsa.KeyPair.generate();
    const pt = kp.public_key.toUncompressedSec1();
    const x_b64 = try b64urlEncode(gpa, pt[1..33]);
    defer gpa.free(x_b64);
    const y_b64 = try b64urlEncode(gpa, pt[33..65]);
    defer gpa.free(y_b64);

    // Compute the expected hash independently in the test, rather than via
    // the function under test, to actually exercise correctness.
    const expected_json = try std.fmt.allocPrint(gpa, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 });
    defer gpa.free(expected_json);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(expected_json, &expected, .{});

    const got = try jwkThumbprint(gpa, x_b64, y_b64);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "acme: CSR build + parse + signature verify" {
    const gpa = std.testing.allocator;
    const kp = Ecdsa.KeyPair.generate();
    const domain = "example.test";

    const der = try buildCsrDer(gpa, domain, kp);
    defer gpa.free(der);

    const parsed = try parseCsrDer(der);
    try std.testing.expect(parsed.version_zero);
    try std.testing.expectEqualStrings(domain, parsed.cn);
    try std.testing.expectEqualStrings(domain, parsed.san_dns);
    try parsed.signature.verify(parsed.tbs, kp.public_key);
}

test "acme: X.509 notAfter parses year 2081 from tls_cert.pem fixture" {
    const gpa = std.testing.allocator;
    const pem = std.fs.cwd().readFileAlloc(gpa, "testdata/tls_cert.pem", 1 << 16) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer gpa.free(pem);

    const not_after = try certNotAfterEpoch(gpa, pem);
    try std.testing.expect(not_after > 0);
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(not_after) };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    try std.testing.expectEqual(@as(std.time.epoch.Year, 2081), year_day.year);
}

test "acme: HTTP-01 challenge server serves token, 404s elsewhere" {
    const gpa = std.testing.allocator;
    const token = "test-token-123";
    const key_auth = "test-token-123.thumbprint-abc";

    const srv = try ChallengeServer.start(gpa, 0, token, key_auth);
    defer srv.stop(gpa);
    // Bound to 0.0.0.0 (all interfaces, matching production); connect to
    // loopback on the same ephemeral port instead of the wildcard address,
    // since some platforms (Windows) reject connecting to 0.0.0.0 itself.
    const bound = try std.net.Address.parseIp("127.0.0.1", srv.listener.listen_address.getPort());

    {
        const stream = try std.net.tcpConnectToAddress(bound);
        defer stream.close();
        var write_buf: [512]u8 = undefined;
        var sw = stream.writer(&write_buf);
        try sw.interface.writeAll("GET /.well-known/acme-challenge/test-token-123 HTTP/1.1\r\nHost: x\r\n\r\n");
        try sw.interface.flush();

        var read_buf: [512]u8 = undefined;
        var sr = stream.reader(&read_buf);
        const input = sr.interface();
        try input.fillMore();
        const resp = input.buffered();
        try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200"));
        try std.testing.expect(std.mem.indexOf(u8, resp, key_auth) != null);
    }
    {
        const stream = try std.net.tcpConnectToAddress(bound);
        defer stream.close();
        var write_buf: [512]u8 = undefined;
        var sw = stream.writer(&write_buf);
        try sw.interface.writeAll("GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
        try sw.interface.flush();

        var read_buf: [512]u8 = undefined;
        var sr = stream.reader(&read_buf);
        const input = sr.interface();
        try input.fillMore();
        const resp = input.buffered();
        try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 404"));
    }
}

test "acme: account/domain key PEM round-trip" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const kp1 = try ensureKeyFile(gpa, tmp.dir, "account_key.pem");
    const kp2 = try ensureKeyFile(gpa, tmp.dir, "account_key.pem");
    try std.testing.expectEqualSlices(u8, &kp1.secret_key.toBytes(), &kp2.secret_key.toBytes());
    try std.testing.expectEqualSlices(u8, &kp1.public_key.toUncompressedSec1(), &kp2.public_key.toUncompressedSec1());
}
