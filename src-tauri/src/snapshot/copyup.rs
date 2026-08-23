//! `CopyUpSimulationBackend` — the MVP last-resort `SimulationBackend`
//! fallback (§14.4): "Directory-based copy-on-write with an explicit
//! changed-path journal. Correct but with higher snapshot cost; used only
//! when neither overlay option passes the self-test."
//!
//! Unlike `overlayfs.rs`/`fuse_overlay.rs`, this backend needs no kernel
//! or FUSE support at all — every operation here is a plain directory
//! create/rename/remove, so this is the one `SimulationBackend`
//! implementation that's **fully real-tested** in this project's
//! development environment (no unverified-here caveat, unlike almost
//! everything in `sandbox/`).
//!
//! "Explicit changed-path journal" (§14.4's phrase) is not yet built in
//! this pass: sealing renames the whole active-write directory into a
//! checkpoint wholesale rather than tracking a minimal changed-file list,
//! and `mount_view` returns the layer directories for a caller to search
//! itself rather than a merged read/write API with whiteout support for
//! deletions. Both are real future work — see `backend.rs`'s module docs
//! for why the merged read/write API specifically is scoped to Build
//! order phase 6, not this one. What *is* real here is the layer
//! lifecycle itself: create, seal, discard, restore, size — which is what
//! Build order phase 3 ("layer model... stack management") actually asks
//! for.

use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::snapshot::backend::{
    CheckpointId, LayerId, LayerStack, MountedView, SimulationBackend, SimulationError,
    TransientLayerId, WriteTarget,
};

/// Manages one session's on-disk layers under `layers_root`:
/// `layers_root/checkpoints/<ulid>/` and `layers_root/transient/<ulid>/`.
/// The consolidated base and the active write layer are **not** owned by
/// this struct — they live wherever the caller's `LayerStack` says (the
/// base is seed content this backend never creates or deletes; the active
/// write layer's *directory* is created here on `new`/`restore_to`/`seal`,
/// but its *path* is caller-chosen).
pub struct CopyUpSimulationBackend {
    layers_root: PathBuf,
}

impl CopyUpSimulationBackend {
    pub fn new(layers_root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(layers_root.join("checkpoints"))?;
        std::fs::create_dir_all(layers_root.join("transient"))?;
        Ok(CopyUpSimulationBackend { layers_root })
    }

    /// `pub(crate)` so `snapshot::retention`'s and `rollback`'s tests can
    /// assert a checkpoint's own directory is actually gone (or intact),
    /// not just absent-or-present in `LayerStack.checkpoints`.
    pub(crate) fn checkpoint_path(&self, id: CheckpointId) -> PathBuf {
        self.layers_root.join("checkpoints").join(id.0.to_string())
    }

    fn transient_path(&self, id: TransientLayerId) -> PathBuf {
        self.layers_root.join("transient").join(id.0.to_string())
    }
}

impl SimulationBackend for CopyUpSimulationBackend {
    fn mount_view(
        &self,
        layers: &LayerStack,
        write: WriteTarget,
    ) -> Result<MountedView, SimulationError> {
        let write_path = match write {
            WriteTarget::ActiveWrite => layers.active_write.clone(),
            WriteTarget::Transient(id) => self.transient_path(id),
        };
        if !write_path.is_dir() {
            return Err(SimulationError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "write layer directory does not exist: {}",
                    write_path.display()
                ),
            )));
        }

        let mut mount_layers = vec![write_path];
        mount_layers.extend(
            layers
                .checkpoints
                .iter()
                .rev()
                .map(|(_, path)| path.clone()),
        );
        mount_layers.push(layers.base.clone());
        Ok(MountedView {
            layers: mount_layers,
        })
    }

    fn seal_active_layer(&self, layers: &mut LayerStack) -> Result<CheckpointId, SimulationError> {
        let id = CheckpointId(Ulid::new());
        let checkpoint_path = self.checkpoint_path(id);

        // Seal by rename (§23.1: "not a copy of the filesystem" — a
        // rename within the same filesystem is O(1), not proportional to
        // content size), then create a fresh empty active write layer at
        // the *original* path.
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
        // `None` -> discard from index 0 (every checkpoint). `Some(id)` ->
        // discard everything *after* that checkpoint's index, keeping it.
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

        // Strictly LIFO, matching §23.5. `drain` here both removes them
        // from the stack and gives us the paths to delete.
        for (_, path) in layers.checkpoints.drain(discard_from..) {
            std::fs::remove_dir_all(&path)?;
        }

        // The current active write layer is discarded and replaced with a
        // fresh empty one *above* the target checkpoint — §14.3's
        // "Rollback: discard W' entirely and create a fresh empty write
        // layer above C_k." The target checkpoint itself is never
        // modified; it stays sealed.
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
        Ok(directory_size_bytes(&path)?)
    }
}

/// `pub(super)` so `overlayfs.rs` (which has no mount-independent way to
/// size a directory of its own — the size of a checkpoint is the same
/// question regardless of which backend mounts it) can reuse this instead
/// of duplicating a directory-walk.
pub(super) fn directory_size_bytes(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += directory_size_bytes(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_stack(root: &Path) -> (CopyUpSimulationBackend, LayerStack) {
        let backend = CopyUpSimulationBackend::new(root.join("layers")).unwrap();
        let base = root.join("base");
        std::fs::create_dir_all(&base).unwrap();
        let active_write = root.join("write");
        std::fs::create_dir_all(&active_write).unwrap();
        (
            backend,
            LayerStack {
                base,
                checkpoints: Vec::new(),
                active_write,
            },
        )
    }

    #[test]
    fn seal_moves_active_write_into_a_checkpoint_and_creates_a_fresh_one() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        std::fs::write(stack.active_write.join("a.txt"), b"hello").unwrap();
        let id = backend.seal_active_layer(&mut stack).unwrap();

        assert_eq!(stack.checkpoints, vec![(id, backend.checkpoint_path(id))]);
        assert!(
            stack.active_write.is_dir(),
            "a fresh active write layer must exist after sealing"
        );
        assert!(
            std::fs::read_dir(&stack.active_write)
                .unwrap()
                .next()
                .is_none(),
            "the fresh active write layer must be empty"
        );
        assert_eq!(
            std::fs::read_to_string(backend.checkpoint_path(id).join("a.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn multiple_seals_build_an_ordered_stack() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        std::fs::write(stack.active_write.join("first.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("second.txt"), b"2").unwrap();
        let id2 = backend.seal_active_layer(&mut stack).unwrap();

        assert_eq!(
            stack
                .checkpoints
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![id1, id2]
        );
    }

    #[test]
    fn create_transient_layer_creates_an_isolated_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());

        let id = backend.create_transient_layer(&stack).unwrap();
        let path = backend.transient_path(id);
        assert!(path.is_dir());
        assert!(std::fs::read_dir(&path).unwrap().next().is_none());
    }

    #[test]
    fn discard_layer_removes_a_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        let id = backend.seal_active_layer(&mut stack).unwrap();
        assert!(backend.checkpoint_path(id).is_dir());

        backend.discard_layer(LayerId::Checkpoint(id)).unwrap();
        assert!(!backend.checkpoint_path(id).exists());
    }

    #[test]
    fn discard_layer_removes_a_transient_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        let id = backend.create_transient_layer(&stack).unwrap();
        assert!(backend.transient_path(id).is_dir());

        backend.discard_layer(LayerId::Transient(id)).unwrap();
        assert!(!backend.transient_path(id).exists());
    }

    #[test]
    fn restore_to_discards_layers_above_the_target_and_resets_active_write() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"2").unwrap();
        let id2 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("c.txt"), b"uncommitted").unwrap();

        backend.restore_to(&mut stack, Some(id1)).unwrap();

        assert_eq!(stack.checkpoints, vec![(id1, backend.checkpoint_path(id1))]);
        assert!(
            !backend.checkpoint_path(id2).exists(),
            "checkpoint above the restore target must be discarded"
        );
        assert!(
            std::fs::read_dir(&stack.active_write)
                .unwrap()
                .next()
                .is_none(),
            "active write layer must be reset to empty after restore"
        );
        // The target checkpoint itself is untouched.
        assert_eq!(
            std::fs::read_to_string(backend.checkpoint_path(id1).join("a.txt")).unwrap(),
            "1"
        );
    }

    #[test]
    fn restore_to_an_unknown_checkpoint_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        let bogus = CheckpointId(Ulid::new());
        let result = backend.restore_to(&mut stack, Some(bogus));
        assert!(matches!(result, Err(SimulationError::UnknownCheckpoint)));
    }

    #[test]
    fn restore_to_none_discards_every_checkpoint_back_to_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"2").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        backend.restore_to(&mut stack, None).unwrap();

        assert!(stack.checkpoints.is_empty());
        assert!(!backend.checkpoint_path(id1).exists());
        assert!(std::fs::read_dir(&stack.active_write)
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn layer_size_bytes_sums_file_sizes_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        std::fs::write(stack.active_write.join("a.txt"), b"12345").unwrap();
        std::fs::create_dir(stack.active_write.join("sub")).unwrap();
        std::fs::write(stack.active_write.join("sub/b.txt"), b"1234567890").unwrap();
        let id = backend.seal_active_layer(&mut stack).unwrap();

        let size = backend.layer_size_bytes(LayerId::Checkpoint(id)).unwrap();
        assert_eq!(size, 15);
    }

    #[test]
    fn mount_view_orders_write_layer_then_checkpoints_newest_first_then_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());

        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        let id2 = backend.seal_active_layer(&mut stack).unwrap();

        let view = backend
            .mount_view(&stack, WriteTarget::ActiveWrite)
            .unwrap();
        assert_eq!(
            view.layers,
            vec![
                stack.active_write.clone(),
                backend.checkpoint_path(id2),
                backend.checkpoint_path(id1),
                stack.base.clone()
            ]
        );
    }

    #[test]
    fn mount_view_can_target_a_transient_layer_instead_of_active_write() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        let transient_id = backend.create_transient_layer(&stack).unwrap();

        let view = backend
            .mount_view(&stack, WriteTarget::Transient(transient_id))
            .unwrap();
        assert_eq!(view.layers[0], backend.transient_path(transient_id));
        assert_eq!(view.layers.last().unwrap(), &stack.base);
    }

    #[test]
    fn resolution_order_matches_mount_view_for_active_write() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        backend.seal_active_layer(&mut stack).unwrap();

        let view = backend
            .mount_view(&stack, WriteTarget::ActiveWrite)
            .unwrap();
        assert_eq!(view.layers, stack.resolution_order());
    }
}
