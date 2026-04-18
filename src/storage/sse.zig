//! SSE-S3 chunked AES-256-GCM at rest.
//!
//! On-disk format for an encrypted object:
//!   [0..8]   magic = "SIMPSSE1"
//!   [8..12]  chunk_size (u32 LE) — plaintext bytes per chunk
//!   [12..16] reserved (zero)
//!   then repeated chunks until end of file:
//!     [12 bytes] random nonce
//!     [N bytes ] ciphertext  (1..=chunk_size)
//!     [16 bytes] AES-GCM tag
//!
//! Each chunk uses additional-authenticated-data = chunk index (u64 LE) so
//! reordering a chunk fails authentication.
//!
//! The data-encryption key (DEK) is per-object random 32 bytes, wrapped with
//! the master key via a separate AES-256-GCM (random 12-byte nonce, no AAD).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Io = std.Io;

pub const magic = "SIMPSSE1";
pub const header_size: usize = 16;
pub const tag_size: usize = Aes256Gcm.tag_length; // 16
pub const nonce_size: usize = Aes256Gcm.nonce_length; // 12
pub const dek_size: usize = Aes256Gcm.key_length; // 32
pub const default_chunk_size: u32 = 64 * 1024;

pub const wrapped_dek_len: usize = dek_size + tag_size; // 48

pub const Error = error{
    DecryptFailed,
    BadHeader,
    Truncated,
    OutOfMemory,
    Internal,
};

pub fn generateDek() [dek_size]u8 {
    var k: [dek_size]u8 = undefined;
    std.crypto.random.bytes(&k);
    return k;
}

/// Wrap (encrypt) a DEK under the master key. Returns 48-byte ciphertext||tag
/// and the random nonce used.
pub fn wrapDek(master: *const [32]u8, dek: *const [dek_size]u8) struct {
    wrapped: [wrapped_dek_len]u8,
    nonce: [nonce_size]u8,
} {
    var nonce: [nonce_size]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    var ct: [dek_size]u8 = undefined;
    var tag: [tag_size]u8 = undefined;
    Aes256Gcm.encrypt(&ct, &tag, dek, &.{}, nonce, master.*);
    var out: [wrapped_dek_len]u8 = undefined;
    @memcpy(out[0..dek_size], &ct);
    @memcpy(out[dek_size..], &tag);
    return .{ .wrapped = out, .nonce = nonce };
}

pub fn unwrapDek(
    master: *const [32]u8,
    wrapped: *const [wrapped_dek_len]u8,
    nonce: *const [nonce_size]u8,
) Error![dek_size]u8 {
    var dek: [dek_size]u8 = undefined;
    const ct: *const [dek_size]u8 = wrapped[0..dek_size];
    const tag: *const [tag_size]u8 = wrapped[dek_size..][0..tag_size];
    Aes256Gcm.decrypt(&dek, ct, tag.*, &.{}, nonce.*, master.*) catch return error.DecryptFailed;
    return dek;
}

fn writeHeader(writer: *Io.Writer, chunk_size: u32) !void {
    try writer.writeAll(magic);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], chunk_size, .little);
    std.mem.writeInt(u32, buf[4..8], 0, .little);
    try writer.writeAll(&buf);
}

/// Public alias for `writeHeader` so callers (objects.putObjectStreaming) can
/// write the SSE header before driving their own per-chunk encrypt loop.
pub fn writeHeaderTo(writer: *Io.Writer, chunk_size: u32) !void {
    return writeHeader(writer, chunk_size);
}

fn readHeader(reader: *Io.Reader) !u32 {
    var hdr: [header_size]u8 = undefined;
    try reader.readSliceAll(&hdr);
    if (!std.mem.eql(u8, hdr[0..8], magic)) return error.BadHeader;
    return std.mem.readInt(u32, hdr[8..12], .little);
}

pub fn aadForChunk(index: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, index, .little);
    return buf;
}

/// Encrypt `plaintext_len` bytes from `reader` into `writer` using chunked
/// AES-256-GCM. Returns total ciphertext bytes written (including header).
pub fn encryptStream(
    reader: *Io.Reader,
    writer: *Io.Writer,
    plaintext_len: u64,
    dek: *const [dek_size]u8,
    chunk_size: u32,
) !u64 {
    try writeHeader(writer, chunk_size);
    var written: u64 = header_size;

    var chunk_buf = try std.heap.page_allocator.alloc(u8, chunk_size);
    defer std.heap.page_allocator.free(chunk_buf);
    var ct_buf = try std.heap.page_allocator.alloc(u8, chunk_size);
    defer std.heap.page_allocator.free(ct_buf);

    var remaining = plaintext_len;
    var index: u64 = 0;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, @as(u64, chunk_size)));
        try reader.readSliceAll(chunk_buf[0..want]);
        var nonce: [nonce_size]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        var tag: [tag_size]u8 = undefined;
        const aad = aadForChunk(index);
        Aes256Gcm.encrypt(ct_buf[0..want], &tag, chunk_buf[0..want], &aad, nonce, dek.*);
        try writer.writeAll(&nonce);
        try writer.writeAll(ct_buf[0..want]);
        try writer.writeAll(&tag);
        written += nonce_size + want + tag_size;
        remaining -= want;
        index += 1;
    }
    return written;
}

/// Stream-decrypt an encrypted file into `writer`, emitting exactly
/// `plaintext_len` bytes. Reader must be positioned at start of file (header).
pub fn decryptStream(
    reader: *Io.Reader,
    writer: *Io.Writer,
    plaintext_len: u64,
    dek: *const [dek_size]u8,
) !void {
    const chunk_size = try readHeader(reader);
    if (chunk_size == 0 or chunk_size > 16 * 1024 * 1024) return error.BadHeader;

    var ct_buf = try std.heap.page_allocator.alloc(u8, chunk_size);
    defer std.heap.page_allocator.free(ct_buf);
    var pt_buf = try std.heap.page_allocator.alloc(u8, chunk_size);
    defer std.heap.page_allocator.free(pt_buf);

    var remaining = plaintext_len;
    var index: u64 = 0;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, @as(u64, chunk_size)));
        var nonce: [nonce_size]u8 = undefined;
        try reader.readSliceAll(&nonce);
        try reader.readSliceAll(ct_buf[0..want]);
        var tag: [tag_size]u8 = undefined;
        try reader.readSliceAll(&tag);
        const aad = aadForChunk(index);
        Aes256Gcm.decrypt(pt_buf[0..want], ct_buf[0..want], tag, &aad, nonce, dek.*) catch return error.DecryptFailed;
        try writer.writeAll(pt_buf[0..want]);
        remaining -= want;
        index += 1;
    }
}

test "roundtrip wrap/unwrap dek" {
    var master: [32]u8 = undefined;
    std.crypto.random.bytes(&master);
    var dek: [dek_size]u8 = undefined;
    std.crypto.random.bytes(&dek);
    const w = wrapDek(&master, &dek);
    const dek2 = try unwrapDek(&master, &w.wrapped, &w.nonce);
    try std.testing.expectEqualSlices(u8, &dek, &dek2);
}

test "roundtrip encrypt/decrypt stream" {
    const plaintext = "Hello, SSE-S3 chunked AES-GCM world! " ** 200;
    var dek: [dek_size]u8 = undefined;
    std.crypto.random.bytes(&dek);

    var enc_buf = std.ArrayList(u8){};
    defer enc_buf.deinit(std.testing.allocator);

    var pt_reader = Io.Reader.fixed(plaintext);
    var enc_writer = Io.Writer.Allocating.init(std.testing.allocator);
    defer enc_writer.deinit();
    _ = try encryptStream(&pt_reader, &enc_writer.writer, plaintext.len, &dek, 64);

    const ciphertext = enc_writer.written();
    var dec_reader = Io.Reader.fixed(ciphertext);
    var dec_writer = Io.Writer.Allocating.init(std.testing.allocator);
    defer dec_writer.deinit();
    try decryptStream(&dec_reader, &dec_writer.writer, plaintext.len, &dek);
    try std.testing.expectEqualStrings(plaintext, dec_writer.written());
}

test "tampered chunk fails auth" {
    const plaintext = "secret data here, top secret indeed";
    var dek: [dek_size]u8 = undefined;
    std.crypto.random.bytes(&dek);

    var pt_reader = Io.Reader.fixed(plaintext);
    var enc_writer = Io.Writer.Allocating.init(std.testing.allocator);
    defer enc_writer.deinit();
    _ = try encryptStream(&pt_reader, &enc_writer.writer, plaintext.len, &dek, 64);

    const ct = enc_writer.written();
    // Flip a byte in the ciphertext payload (past header + nonce).
    ct[header_size + nonce_size] ^= 0x01;

    var dec_reader = Io.Reader.fixed(ct);
    var dec_writer = Io.Writer.Allocating.init(std.testing.allocator);
    defer dec_writer.deinit();
    try std.testing.expectError(error.DecryptFailed, decryptStream(&dec_reader, &dec_writer.writer, plaintext.len, &dek));
}
