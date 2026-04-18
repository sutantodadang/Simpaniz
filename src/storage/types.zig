const xml = @import("../xml.zig");

pub const Error = error{
    BucketNotFound,
    BucketNotEmpty,
    BucketAlreadyExists,
    ObjectNotFound,
    InvalidKey,
    InvalidPart,
    UploadNotFound,
    BadDigest,
    OutOfMemory,
    Internal,
};

pub const EncryptionInfo = struct {
    /// Algorithm name; only "AES256" is supported (SSE-S3).
    alg: []const u8,
    /// Chunk size used for chunked AEAD (plaintext bytes per chunk).
    chunk_size: u32,
    /// Plaintext size of the object in bytes (file on disk is larger).
    plaintext_size: u64,
    /// Base64-encoded data-encryption key, AES-GCM-wrapped under the master
    /// key (ciphertext || 16-byte tag, 48 bytes total before base64).
    wrapped_dek_b64: []const u8,
    /// Base64-encoded 12-byte nonce used to wrap the DEK.
    wrap_nonce_b64: []const u8,
};

pub const ObjectMeta = struct {
    content_type: []const u8,
    /// 32-char hex MD5 of plaintext, or "{hex}-{N}" for multipart.
    etag: []const u8,
    size: u64,
    mtime_ns: i128,
    /// Set when the object is stored encrypted (SSE-S3).
    encryption: ?EncryptionInfo = null,
};

pub const BucketSummary = struct {
    name: []const u8,
    creation_ns: i128,
};

pub const ListOpts = struct {
    prefix: []const u8 = "",
    delimiter: []const u8 = "",
    continuation_token: []const u8 = "",
    start_after: []const u8 = "",
    max_keys: usize = 1000,
};

pub const ListPage = struct {
    objects: []xml.ObjectInfo,
    common_prefixes: [][]const u8,
    is_truncated: bool,
    next_continuation_token: []const u8,
};

pub const PutInput = struct {
    bucket: []const u8,
    key: []const u8,
    content_type: []const u8 = "application/octet-stream",
    content_length: u64,
    /// Optional caller-supplied Content-MD5 (base64) to verify against payload.
    expected_md5_b64: []const u8 = "",
    /// Optional caller-supplied x-amz-content-sha256 to verify against payload.
    expected_sha256_hex: []const u8 = "",
    /// When non-null, encrypt at rest using SSE-S3 chunked AES-256-GCM.
    /// Pointer must remain valid for the duration of the call.
    master_key: ?*const [32]u8 = null,
};

pub const PartCopyRange = struct { start: u64, end: u64 };
