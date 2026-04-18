//! Public façade for the cluster (multi-node) subsystem.
//!
//! The implementation lives under `src/cluster/`. This file re-exports
//! the public API.
//!
//! Status: foundational primitives only. Distributed PUT/GET orchestrator,
//! peer HTTP client, internal shard API, and self-healing daemon are
//! scaffolded as separate phases on top of these primitives.

const reed_solomon_mod = @import("cluster/reed_solomon.zig");
const rendezvous_mod = @import("cluster/rendezvous.zig");
const config_mod = @import("cluster/config.zig");
const transport_mod = @import("cluster/transport.zig");
const orchestrator_mod = @import("cluster/orchestrator.zig");
const disk_store_mod = @import("cluster/disk_store.zig");
const http_transport_mod = @import("cluster/http_transport.zig");
const internal_handler_mod = @import("cluster/internal_handler.zig");
const runtime_mod = @import("cluster/runtime.zig");
const heal_mod = @import("cluster/heal.zig");
const replication_mod = @import("cluster/replication.zig");

// ── Reed-Solomon erasure coding ─────────────────────────────────────────────
pub const Codec = reed_solomon_mod.Codec;
pub const max_shards = reed_solomon_mod.max_shards;

// ── Rendezvous (HRW) hashing ────────────────────────────────────────────────
pub const Placement = rendezvous_mod.Placement;
pub const pickNodes = rendezvous_mod.pick;

// ── Cluster identity / config ───────────────────────────────────────────────
pub const ClusterConfig = config_mod.ClusterConfig;
pub const Peer = config_mod.Peer;
pub const loadConfig = config_mod.load;

// ── Shard transport ─────────────────────────────────────────────────────────
pub const Transport = transport_mod.Transport;
pub const ShardId = transport_mod.ShardId;
pub const LocalTransport = transport_mod.LocalTransport;
pub const HttpTransport = http_transport_mod.HttpTransport;

// ── Distributed orchestrator ────────────────────────────────────────────────
pub const Orchestrator = orchestrator_mod.Orchestrator;
pub const PutResult = orchestrator_mod.PutResult;

// ── Runtime + on-disk store + internal endpoint ─────────────────────────────
pub const ClusterRuntime = runtime_mod.ClusterRuntime;
pub const ObjectMeta = runtime_mod.ObjectMeta;
pub const DiskStore = disk_store_mod;
pub const internalHandler = internal_handler_mod.handle;
pub const isInternalPath = internal_handler_mod.matches;
pub const HealDaemon = heal_mod;
pub const Replicator = replication_mod.Replicator;

test {
    const std = @import("std");
    std.testing.refAllDecls(reed_solomon_mod);
    std.testing.refAllDecls(rendezvous_mod);
    std.testing.refAllDecls(config_mod);
    std.testing.refAllDecls(transport_mod);
    std.testing.refAllDecls(orchestrator_mod);
    std.testing.refAllDecls(disk_store_mod);
    std.testing.refAllDecls(internal_handler_mod);
    std.testing.refAllDecls(runtime_mod);
    std.testing.refAllDecls(replication_mod);
}
