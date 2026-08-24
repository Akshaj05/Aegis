// Layer-stack types (checkpoints, transient layers, mounted views) and the
// `SimulationBackend` trait implemented by each snapshot backend.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteTarget {
    ActiveWrite,
    Transient(TransientLayerId),
}

#[derive(Debug, Clone)]
pub struct LayerStack {
    pub base: PathBuf,
    pub checkpoints: Vec<(CheckpointId, PathBuf)>,
    pub active_write: PathBuf,
}

impl LayerStack {
    pub fn resolution_order(&self) -> Vec<PathBuf> {
        let mut order = vec![self.active_write.clone()];
        order.extend(self.checkpoints.iter().rev().map(|(_, path)| path.clone()));
        order.push(self.base.clone());
        order
    }
}

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
    fn restore_to(
        &self,
        layers: &mut LayerStack,
        id: Option<CheckpointId>,
    ) -> Result<(), SimulationError>;
    fn layer_size_bytes(&self, id: LayerId) -> Result<u64, SimulationError>;
}
