//! Public façade for the filesystem-backed storage backend.
//!
//! The implementation lives under `src/storage/`. This file re-exports
//! the public API so call sites can keep using `@import("storage.zig")`.

const types = @import("storage/types.zig");
const buckets = @import("storage/buckets.zig");
const objects = @import("storage/objects.zig");
const multipart = @import("storage/multipart.zig");
const tagging = @import("storage/tagging.zig");
const policy = @import("storage/policy.zig");
const lifecycle_mod = @import("storage/lifecycle.zig");
const scrub_mod = @import("storage/scrub.zig");
const versioning_mod = @import("storage/versioning.zig");
const object_lock_mod = @import("storage/object_lock.zig");
const object_lock_config_mod = @import("storage/object_lock_config.zig");

// ── Types ────────────────────────────────────────────────────────────────────
pub const Error = types.Error;
pub const ObjectMeta = types.ObjectMeta;
pub const BucketSummary = types.BucketSummary;
pub const ListOpts = types.ListOpts;
pub const ListPage = types.ListPage;
pub const PutInput = types.PutInput;
pub const PartCopyRange = types.PartCopyRange;

// ── Bucket ops ───────────────────────────────────────────────────────────────
pub const createBucket = buckets.createBucket;
pub const deleteBucket = buckets.deleteBucket;
pub const bucketExists = buckets.bucketExists;
pub const listBuckets = buckets.listBuckets;

// ── Object ops ───────────────────────────────────────────────────────────────
pub const putObjectStreaming = objects.putObjectStreaming;
pub const openObject = objects.openObject;
pub const headObject = objects.headObject;
pub const deleteObject = objects.deleteObject;
pub const copyObject = objects.copyObject;
pub const listObjects = objects.listObjects;

// ── Multipart ────────────────────────────────────────────────────────────────
pub const createUpload = multipart.createUpload;
pub const putPart = multipart.putPart;
pub const completeUpload = multipart.completeUpload;
pub const abortUpload = multipart.abortUpload;
pub const listParts = multipart.listParts;
pub const listMultipartUploads = multipart.listMultipartUploads;
pub const uploadPartCopy = multipart.uploadPartCopy;

// ── Tagging ──────────────────────────────────────────────────────────────────
pub const putObjectTagging = tagging.putObjectTagging;
pub const getObjectTagging = tagging.getObjectTagging;
pub const deleteObjectTagging = tagging.deleteObjectTagging;

// ── Bucket policy ────────────────────────────────────────────────────────────
pub const putBucketPolicy = policy.putBucketPolicy;
pub const getBucketPolicy = policy.getBucketPolicy;
pub const deleteBucketPolicy = policy.deleteBucketPolicy;

// ── Lifecycle ────────────────────────────────────────────────────────────────
pub const putBucketLifecycle = lifecycle_mod.putBucketLifecycle;
pub const getBucketLifecycle = lifecycle_mod.getBucketLifecycle;
pub const deleteBucketLifecycle = lifecycle_mod.deleteBucketLifecycle;
pub const sweepLifecycle = lifecycle_mod.sweep;

// ── Bitrot scrubber ──────────────────────────────────────────────────────────
pub const scrubOnce = scrub_mod.runOnce;
pub const ScrubStats = scrub_mod.ScrubStats;

// ── Versioning ───────────────────────────────────────────────────────────────
pub const VersionState = versioning_mod.State;
pub const getBucketVersioning = versioning_mod.getState;
pub const putBucketVersioning = versioning_mod.putState;
pub const snapshotCurrentVersion = versioning_mod.snapshotCurrent;
pub const openVersionData = versioning_mod.openVersionData;
pub const deleteObjectVersion = versioning_mod.deleteVersion;
pub const readObjectVersionMeta = versioning_mod.readVersionMeta;
pub const addDeleteMarker = versioning_mod.addDeleteMarker;
pub const listObjectVersions = versioning_mod.listVersions;
pub const VersionEntry = versioning_mod.VersionEntry;

// ── Object Lock ──────────────────────────────────────────────────────────────
pub const RetentionMode = object_lock_mod.Mode;
pub const Retention = object_lock_mod.Retention;
pub const putObjectRetention = object_lock_mod.putRetention;
pub const getObjectRetention = object_lock_mod.getRetention;
pub const putObjectLegalHold = object_lock_mod.putLegalHold;
pub const objectLegalHoldOn = object_lock_mod.legalHoldOn;
pub const objectIsProtected = object_lock_mod.isProtected;

// ── Bucket Object-Lock config (default retention) ────────────────────────────
pub const ObjectLockConfig = object_lock_config_mod.Config;
pub const putBucketObjectLock = object_lock_config_mod.put;
pub const getBucketObjectLock = object_lock_config_mod.get;
pub const buildBucketObjectLockXml = object_lock_config_mod.buildXml;

// Pull in all submodule tests under this façade.
test {
    const std = @import("std");
    std.testing.refAllDecls(@import("storage/internal.zig"));
    std.testing.refAllDecls(buckets);
    std.testing.refAllDecls(@import("storage/sse.zig"));
    std.testing.refAllDecls(lifecycle_mod);
    std.testing.refAllDecls(scrub_mod);
    std.testing.refAllDecls(versioning_mod);
    std.testing.refAllDecls(object_lock_mod);
    std.testing.refAllDecls(object_lock_config_mod);
}
