// `SimulationBackend` implementation backed by kernel OverlayFS, using
// multiple `lowerdir` entries instead of nesting overlay mounts.

use std::path::PathBuf;

use nix::mount::MsFlags;
use ulid::Ulid;

use crate::sandbox::backend::PrimitiveStatus;
use crate::sandbox::syscalls::run_probe_in_child;
use crate::snapshot::backend::{
    CheckpointId, LayerId, LayerStack, MountedView, SimulationBackend, SimulationError,
    TransientLayerId, WriteTarget,
};

pub struct OverlayFsSimulationBackend {
    layers_root: PathBuf,
    mount_point: PathBuf,
}

impl OverlayFsSimulationBackend {
    pub fn new(layers_root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(layers_root.join("checkpoints"))?;
        std::fs::create_dir_all(layers_root.join("transient"))?;
        std::fs::create_dir_all(layers_root.join("work"))?;
        let mount_point = layers_root.join("merged");
        std::fs::create_dir_all(&mount_point)?;
        Ok(OverlayFsSimulationBackend {
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

impl SimulationBackend for OverlayFsSimulationBackend {
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

        nix::mount::mount(
            Some("overlay"),
            &self.mount_point,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| SimulationError::BackendUnavailable(format!("overlay mount failed: {e}")))?;

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
    let root =
        std::env::temp_dir().join(format!("safeshell-overlay-selftest-{}", ulid::Ulid::new()));
    let root_for_child = root.clone();

    let outcome = run_probe_in_child(move || {
        let root = root_for_child;
        let lower1 = root.join("lower1");
        let lower2 = root.join("lower2");
        let upper = root.join("upper");
        let work = root.join("work");
        let merged = root.join("merged");

        for dir in [&lower1, &lower2, &upper, &work, &merged] {
            if std::fs::create_dir_all(dir).is_err() {
                return 1;
            }
        }
        if std::fs::write(lower2.join("from_lower.txt"), b"lower content").is_err() {
            return 2;
        }

        let options = format!(
            "lowerdir={}:{},upperdir={},workdir={}",
            lower1.display(),
            lower2.display(),
            upper.display(),
            work.display()
        );
        if nix::mount::mount(
            Some("overlay"),
            &merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .is_err()
        {
            return 3;
        }

        if std::fs::write(merged.join("new_file.txt"), b"new content").is_err() {
            return 4;
        }
        if !upper.join("new_file.txt").is_file() {
            return 5;
        }
        if std::fs::read(merged.join("from_lower.txt")).is_err() {
            return 6;
        }

        let _ = nix::mount::umount2(merged.as_path(), nix::mount::MntFlags::MNT_DETACH);
        0
    });

    let _ = std::fs::remove_dir_all(&root);

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(code) => PrimitiveStatus::Unavailable {
            reason: format!(
                "overlay self-test failed at step {code} (1-2=scratch setup, 3=mount, \
                 4-5=write-through-upper check, 6=lower-visibility check)"
            ),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_runs_to_completion_and_does_not_leak_its_scratch_directory() {
        let matching_entries = || -> Vec<_> {
            std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("safeshell-overlay-selftest-")
                })
                .collect()
        };

        let before = matching_entries();
        let status = self_test();
        println!("overlayfs::self_test: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
        let after = matching_entries();

        assert_eq!(
            before.len(),
            after.len(),
            "self_test left a stray scratch directory behind"
        );
    }

    #[test]
    fn lifecycle_methods_work_independent_of_mount_support() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = OverlayFsSimulationBackend::new(tmp.path().join("layers")).unwrap();
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

        backend.discard_layer(LayerId::Checkpoint(id)).unwrap();
        assert!(!backend.checkpoint_path(id).exists());
    }
}
