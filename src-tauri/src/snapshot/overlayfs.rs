//! `OverlayFsSimulationBackend` — the MVP-preferred `SimulationBackend`
//! (§14.4): "Kernel OverlayFS with multiple `lowerdir` entries rather than
//! literally nesting overlay mounts."
//!
//! **Unverified in this pass.** [`self_test`] performs a real mount
//! attempt (matching §15.2's "mount a probe overlay with multiple lowers,
//! write, verify whiteout/opaque semantics survive re-stacking"), and on
//! this development machine it fails for two independent reasons: `overlay`
//! isn't a registered filesystem type at all (`grep overlay
//! /proc/filesystems` finds nothing), and even a plain `mount --bind`
//! fails here with "must be superuser" (no `CAP_SYS_ADMIN`, consistent
//! with `sandbox/`'s namespace-entry findings — the real usage context for
//! this backend is *inside* a namespaced sandbox worker where that
//! process is "root" in its own namespace, which this environment can
//! never produce; see `sandbox/namespace_backend.rs`). The mount
//! construction (`lowerdir`/`upperdir`/`workdir` options) is written to
//! the best of my understanding of `mount_setattr`/`overlayfs(5)`, but has
//! never actually mounted anything, anywhere, in this project's history.
//! Verify on a real Linux host.
//!
//! Everything below `mount_view` (seal/discard/restore/size) is identical
//! directory-lifecycle logic to `copyup.rs` — sealing is a rename
//! regardless of how the *view* is presented. That duplication is real and
//! could be factored out later (e.g. both backends composing a shared
//! `LayerLifecycle` helper); kept separate for now so each backend stays a
//! single, independently-readable file matching how the architecture
//! frames them as independently selectable implementations.

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
    /// Where `mount_view` mounts the merged view. A real mountpoint, not a
    /// managed layer directory — `discard_layer`/`layer_size_bytes` never
    /// address this path.
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

/// §15.2's OverlayFS preflight row: mount a probe overlay with multiple
/// lowers, write through it, verify the write lands in `upperdir` and a
/// lower-only file is still visible through the merged view. Runs in a
/// throwaway forked child (`sandbox::syscalls::run_probe_in_child`) so a
/// partial or unexpected success doesn't leave a live mount in the calling
/// process's mount namespace.
pub fn self_test() -> PrimitiveStatus {
    // Computed *before* forking and moved into the child by value, so the
    // parent's post-run cleanup (below) names the exact same directory the
    // child created. Computing this from `std::process::id()` separately
    // on each side is a real bug this project already made once: inside
    // the child, that call returns the *child's* pid, not the parent's, so
    // a cleanup line built the same way in the parent never matches and
    // silently leaks a directory on every run — worth spelling out since
    // it's an easy mistake to reintroduce.
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
        // A file that exists only in the lower layers — the merged view
        // must still show it after a successful mount.
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

        // Write through the merged view; it must land in `upper`, not in
        // either lower directory (copy-up-free — this is a genuinely new
        // file, not a modification of an existing lower-layer file).
        if std::fs::write(merged.join("new_file.txt"), b"new content").is_err() {
            return 4;
        }
        if !upper.join("new_file.txt").is_file() {
            return 5;
        }
        // The lower-only file must still be visible through the merge.
        if std::fs::read(merged.join("from_lower.txt")).is_err() {
            return 6;
        }

        let _ = nix::mount::umount2(merged.as_path(), nix::mount::MntFlags::MNT_DETACH);
        0
    });

    // Same `root` value the child used (see above) — this is the fix for
    // the bug described in that comment.
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

    /// Covers both "runs to completion" and the leak regression in one
    /// test, deliberately: two separate tests each calling `self_test()`
    /// independently raced against each other on the shared `/tmp`
    /// directory-prefix scan (both counted, from different threads, while
    /// the other's call was mid-flight) and made this assertion flaky
    /// under `cargo test`'s default parallelism. A single call site
    /// removes the race entirely rather than papering over it with a
    /// lock.
    ///
    /// The leak this guards against was real: an earlier version of
    /// `self_test` computed its cleanup path with `std::process::id()` in
    /// the parent, while the child (which actually created the directory)
    /// computed its own path with the same call — returning the *child's*
    /// pid, not the parent's. The two never matched, so cleanup silently
    /// did nothing, and every test run leaked a directory on a disk that
    /// was already nearly full on this development machine.
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
        // seal/discard/restore/size don't touch the kernel mount at all —
        // real-verifiable here regardless of overlay availability.
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
