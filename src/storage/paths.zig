//! On-disk layout constants for the storage backend.
//!
//! Layout (relative to data_dir):
//!   {bucket}/                              — bucket directory
//!   {bucket}/{key}                         — object data
//!   {bucket}/.simpaniz-meta/{key}.json     — object metadata
//!   {bucket}/.simpaniz-mp/{uploadId}/...   — multipart staging
//!   {bucket}/.simpaniz-tmp/                — atomic-write temp area
//!   {bucket}/.simpaniz-tags/{key}.xml      — object tag set XML
//!   {bucket}/.simpaniz-policy.json         — bucket policy JSON

pub const meta_dir = ".simpaniz-meta";
pub const mp_dir = ".simpaniz-mp";
pub const tmp_dir = ".simpaniz-tmp";
pub const tags_dir = ".simpaniz-tags";
pub const reserved_prefix = ".simpaniz-";
pub const policy_file = ".simpaniz-policy.json";
pub const lifecycle_file = ".simpaniz-lifecycle.xml";
pub const versioning_file = ".simpaniz-versioning";
pub const versions_dir = ".simpaniz-versions";
pub const lock_dir = ".simpaniz-lock";
pub const legalhold_dir = ".simpaniz-hold";
pub const lock_config_file = ".simpaniz-lock-config.json";
pub const repl_dir = ".simpaniz-repl";
pub const repl_queue_file = ".simpaniz-repl/queue.log";
