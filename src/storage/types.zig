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
    /// Algorithm name: "AES256" (SSE-S3), "aws:kms" (SSE-KMS, local keyring),
    /// or "SSE-C" (customer-provided key).
    alg: []const u8,
    /// Chunk size used for chunked AEAD (plaintext bytes per chunk).
    chunk_size: u32,
    /// Plaintext size of the object in bytes (file on disk is larger).
    plaintext_size: u64,
    /// Base64-encoded data-encryption key, AES-GCM-wrapped under the wrap
    /// key (master key or SSE-C customer key) (ciphertext || 16-byte tag, 48
    /// bytes total before base64).
    wrapped_dek_b64: []const u8,
    /// Base64-encoded 12-byte nonce used to wrap the DEK.
    wrap_nonce_b64: []const u8,
    /// SSE-C only: base64 MD5 of the customer-supplied key, used to verify
    /// the same key is presented on GET/HEAD. Empty when absent.
    sse_c_key_md5: []const u8 = "",
    /// SSE-KMS only: the (local) key id echoed back to the caller. Empty
    /// when absent.
    kms_key_id: []const u8 = "",
};

pub const ObjectMeta = struct {
    content_type: []const u8,
    /// 32-char hex MD5 of plaintext, or "{hex}-{N}" for multipart.
    etag: []const u8,
    size: u64,
    mtime_ns: i128,
    /// Set when the object is stored encrypted (SSE-S3).
    encryption: ?EncryptionInfo = null,
    /// Lifecycle Transition target, e.g. "GLACIER"/"COLD". Empty when the
    /// object has never been transitioned.
    storage_class: []const u8 = "",
    /// True once lifecycle has moved this object's bytes to a cold tier and
    /// replaced the local file with a zero-byte stub (see tiering.zig).
    tiered: bool = false,
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
    /// When non-null, encrypt at rest using chunked AES-256-GCM. Doubles as
    /// the "wrap key" (KEK) for the per-object DEK: the server master key
    /// for SSE-S3/SSE-KMS, or the customer-supplied key for SSE-C.
    /// Pointer must remain valid for the duration of the call.
    master_key: ?*const [32]u8 = null,
    /// Algorithm to record when `master_key` is set: "AES256", "aws:kms",
    /// or "SSE-C".
    sse_alg: []const u8 = "AES256",
    /// SSE-C only: base64 MD5 of the customer key, stored so GET/HEAD can
    /// verify the same key is presented.
    sse_c_key_md5: []const u8 = "",
    /// SSE-KMS only: key id to echo back to callers.
    kms_key_id: []const u8 = "",
};

pub const PartCopyRange = struct { start: u64, end: u64 };
