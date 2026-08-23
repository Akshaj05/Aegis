//! `SimulationBackend` trait and the layer-stack types it deals in. See
//! `docs/architecture.md` §14.3-§14.4, §23.
//!
//! **Deliberate deviation from the architecture's illustrative Rust**:
//! §14.4's trait sketch takes `&SandboxHandle` in `seal_active_layer`/
//! `create_transient_layer`. This crate's `SandboxHandle`
//! (`sandbox/backend.rs`) is only constructible via a live, namespaced
//! sandbox session — and per `sandbox/namespace_backend.rs`'s doc comment,
//! this dev environment can never produce one. Requiring one here would
//! make the entire layer model untestable in this environment, for a
//! coupling the architecture prose doesn't actually insist on (§14.4 says
//! "no other component may assume a specific *mechanism*" — it's silent on
//! exact trait signatures). So these methods instead take `&LayerStack`/
//! `&mut LayerStack`, an explicit, caller-owned description of where a
//! session's layers live on disk. Wiring `LayerStack` to a live
//! `SandboxHandle` (so the mounted view is what a running sandbox worker
//! actually sees) is Build order phase 6 work ("Simulation + diff... shared
//! handler code path"), not this phase's.
//!
//! `mount_view` here returns only the ordered list of layer directories —
//! it does not also expose a merged read/write API. Building that, and
//! wiring handlers to use it instead of a single root, is explicitly
//! Build order phase 6's job ("Simulation + diff"), not phase 3's ("layer
//! model"). This phase's surface is just stack lifecycle management —
//! creating, sealing, discarding, restoring, and sizing layers, which
//! matches what `docs/CLAUDE.md`'s Build order actually asks for here.

use std::fmt;
use std::path::PathBuf;

use ulid::Ulid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointId(pub Ulid);

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ckpt_{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransientLayerId(pub Ulid);

impl fmt::Display for TransientLayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trans_{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerId {
    Checkpoint(CheckpointId),
    Transient(TransientLayerId),
}

/// Which write layer a mounted view should target. See §14.3: `S`
/// (transient, for simulation) is always a fresh layer; the persistent
/// active write layer `W`/`W'` is what execution writes into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteTarget {
    ActiveWrite,
    Transient(TransientLayerId),
}

/// One session's layer stack, caller-owned (see module docs for why this
/// replaces `&SandboxHandle` in this pass). Mirrors §14.3's diagram:
/// `active_write` is `W`, `checkpoints` is `[C_n, ..., C_1]` conceptually
/// (stored oldest-first here; consumers needing newest-first reverse it),
/// `base` is the consolidated base.
#[derive(Debug, Clone)]
pub struct LayerStack {
    pub base: PathBuf,
    /// Oldest first, matching commit order. The *last* entry is the most
    /// recently sealed checkpoint.
    pub checkpoints: Vec<(CheckpointId, PathBuf)>,
    pub active_write: PathBuf,
}

impl LayerStack {
    /// The stack's directories in resolution order: active write layer
    /// first, then checkpoints newest-first, then the base — matching
    /// §14.3's "read-only lower layers are `[W, C_n, ..., base]`".
    pub fn resolution_order(&self) -> Vec<PathBuf> {
        let mut order = vec![self.active_write.clone()];
        order.extend(self.checkpoints.iter().rev().map(|(_, path)| path.clone()));
        order.push(self.base.clone());
        order
    }
}

/// An ordered list of real directories to search top-to-bottom for a
/// mounted view — see module docs for why this doesn't also carry a
/// merged read/write API in this pass.
#[derive(Debug, Clone)]
pub struct MountedView {
    pub layers: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("checkpoint not found in this layer stack")]
    UnknownCheckpoint,
    #[error("layer filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
}

/// Owns the layer model: transient simulation layers, sealing, checkpoint
/// stacking, discard, and restore. See `docs/architecture.md` §14.4.
pub trait SimulationBackend {
    fn mount_view(
        &self,
        layers: &LayerStack,
        write: WriteTarget,
    ) -> Result<MountedView, SimulationError>;
    fn seal_active_layer(&self, layers: &mut LayerStack) -> Result<CheckpointId, SimulationError>;
    fn create_transient_layer(
        &self,
        layers: &LayerStack,
    ) -> Result<TransientLayerId, SimulationError>;
    fn discard_layer(&self, id: LayerId) -> Result<(), SimulationError>;
    /// Restores to `id`, discarding every checkpoint above it (§23.5) and
    /// resetting the active write layer to empty. `id = None` restores all
    /// the way to the consolidated base, discarding *every* checkpoint —
    /// a deliberate extension beyond §14.4's illustrative
    /// `restore_to(&self, id: CheckpointId)` signature (bare, non-`Option`),
    /// same kind of documented deviation as `LayerStack` itself already
    /// carries (see this file's earlier module doc). It exists because
    /// `rollback/`'s "Undo Last Transaction" (§27.2) needs to express
    /// "no checkpoint remains after undoing the very first one," which a
    /// signature requiring a target `CheckpointId` cannot say.
    fn restore_to(
        &self,
        layers: &mut LayerStack,
        id: Option<CheckpointId>,
    ) -> Result<(), SimulationError>;
    fn layer_size_bytes(&self, id: LayerId) -> Result<u64, SimulationError>;
}
