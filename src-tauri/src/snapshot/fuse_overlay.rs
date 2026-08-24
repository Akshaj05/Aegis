// `SimulationBackend` implementation backed by the external `fuse-overlayfs`
// binary, invoked via `std::process::Command` with an explicit argument
// array (never a shell string).

use std::path::PathBuf;
use std::process::Command;

use ulid::Ulid;

use crate::sandbox::backend::PrimitiveStatus;
use crate::snapshot::backend::{
    CheckpointId, LayerId, LayerStack, MountedView, SimulationBackend, SimulationError,
    TransientLayerId, WriteTarget,
};

pub struct FuseOverlaySimulationBackend {
    layers_root: PathBuf,
    mount_point: PathBuf,
}

impl FuseOverlaySimulationBackend {
    pub fn new(layers_root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(layers_root.join("checkpoints"))?;
        std::fs::create_dir_all(layers_root.join("transient"))?;
        std::fs::create_dir_all(layers_root.join("work"))?;
        let mount_point = layers_root.join("merged");
        std::fs::create_dir_all(&mount_point)?;
        Ok(FuseOverlaySimulationBackend {
            layers_root,
            mount_point,
        })
    }

    fn checkpoint_path(&self, id: CheckpointId) -> PathBuf {
        self.layers_root.join("checkpoints").join(id.0.to_string())
    }

    fn transient_path(&self, id: TransientLayerId) -> PathBuf {
        self.layers_root.join("transient").join(id.0.to_string())
    }
}

impl SimulationBackend for FuseOverlaySimulationBackend {
    fn mount_view(
        &self,
        layers: &LayerStack,
        write: WriteTarget,
    ) -> Result<MountedView, SimulationError> {
        let upper = match write {
            WriteTarget::ActiveWrite => layers.active_write.clone(),
            WriteTarget::Transient(id) => self.transient_path(id),
        };
        let mut lower_dirs: Vec<PathBuf> = layers
            .checkpoints
            .iter()
            .rev()
            .map(|(_, path)| path.clone())
            .collect();
        lower_dirs.push(layers.base.clone());
        let lowerdir_opt = lower_dirs
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");
        let work = self.layers_root.join("work");
        let options = format!(
            "lowerdir={lowerdir_opt},upperdir={},workdir={}",
            upper.display(),
            work.display()
        );

        let status = Command::new("fuse-overlayfs")
            .arg("-o")
            .arg(options)
            .arg(&self.mount_point)
            .status()
            .map_err(|e| {
                SimulationError::BackendUnavailable(format!("fuse-overlayfs not runnable: {e}"))
            })?;

        if !status.success() {
            return Err(SimulationError::BackendUnavailable(format!(
                "fuse-overlayfs exited with {status}"
            )));
        }

        Ok(MountedView {
            layers: vec![self.mount_point.clone()],
        })
    }

    fn seal_active_layer(&self, layers: &mut LayerStack) -> Result<CheckpointId, SimulationError> {
        let id = CheckpointId(Ulid::new());
        let checkpoint_path = self.checkpoint_path(id);
        std::fs::rename(&layers.active_write, &checkpoint_path)?;
        std::fs::create_dir(&layers.active_write)?;
        layers.checkpoints.push((id, checkpoint_path));
        Ok(id)
    }

    fn create_transient_layer(
        &self,
        _layers: &LayerStack,
    ) -> Result<TransientLayerId, SimulationError> {
        let id = TransientLayerId(Ulid::new());
        std::fs::create_dir(self.transient_path(id))?;
        Ok(id)
    }

    fn discard_layer(&self, id: LayerId) -> Result<(), SimulationError> {
        let path = match id {
            LayerId::Checkpoint(cid) => self.checkpoint_path(cid),
            LayerId::Transient(tid) => self.transient_path(tid),
        };
        std::fs::remove_dir_all(&path)?;
        Ok(())
    }

    fn restore_to(
        &self,
        layers: &mut LayerStack,
        id: Option<CheckpointId>,
    ) -> Result<(), SimulationError> {
        let discard_from = match id {
            None => 0,
            Some(id) => {
                let target_index = layers
                    .checkpoints
                    .iter()
                    .position(|(cid, _)| *cid == id)
                    .ok_or(SimulationError::UnknownCheckpoint)?;
                target_index + 1
            }
        };
        for (_, path) in layers.checkpoints.drain(discard_from..) {
            std::fs::remove_dir_all(&path)?;
        }
        if layers.active_write.is_dir() {
            std::fs::remove_dir_all(&layers.active_write)?;
        }
        std::fs::create_dir(&layers.active_write)?;
        Ok(())
    }

    fn layer_size_bytes(&self, id: LayerId) -> Result<u64, SimulationError> {
        let path = match id {
            LayerId::Checkpoint(cid) => self.checkpoint_path(cid),
            LayerId::Transient(tid) => self.transient_path(tid),
        };
        Ok(super::copyup::directory_size_bytes(&path)?)
    }
}

pub fn self_test() -> PrimitiveStatus {
    match Command::new("fuse-overlayfs").arg("--help").output() {
        Ok(output) if output.status.success() => PrimitiveStatus::Ok,
        Ok(output) => PrimitiveStatus::Unavailable {
            reason: format!("fuse-overlayfs --help exited with {}", output.status),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PrimitiveStatus::Unavailable {
            reason: "fuse-overlayfs binary not found on PATH".into(),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("fuse-overlayfs not runnable: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_runs_to_completion() {
        let status = self_test();
        println!("fuse_overlay::self_test: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn lifecycle_methods_work_independent_of_fuse_support() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = FuseOverlaySimulationBackend::new(tmp.path().join("layers")).unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir_all(&base).unwrap();
        let active_write = tmp.path().join("write");
        std::fs::create_dir_all(&active_write).unwrap();
        let mut stack = LayerStack {
            base,
            checkpoints: Vec::new(),
            active_write,
        };

        std::fs::write(stack.active_write.join("a.txt"), b"hi").unwrap();
        let id = backend.seal_active_layer(&mut stack).unwrap();
        assert_eq!(
            backend.layer_size_bytes(LayerId::Checkpoint(id)).unwrap(),
            2
        );
    }
}
