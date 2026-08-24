// Snapshot module root: layer-stack backend trait, its three
// `SimulationBackend` implementations, and checkpoint retention/GC.

pub mod backend;
pub mod copyup;
pub mod fuse_overlay;
pub mod overlayfs;
pub mod retention;
