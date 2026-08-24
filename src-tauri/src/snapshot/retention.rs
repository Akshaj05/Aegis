// Checkpoint retention policy and dependency-aware garbage collection:
// squashes the oldest checkpoint into the consolidated base, resolving
// whiteout markers into real deletions, until the stack is within bounds.

use std::path::Path;

use crate::sandbox::worker::resolver::WHITEOUT_PREFIX;
use crate::snapshot::backend::{
    CheckpointId, LayerId, LayerStack, SimulationBackend, SimulationError,
};

#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub max_checkpoints: usize,
    pub storage_ceiling_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            max_checkpoints: 10,
            storage_ceiling_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcOutcome {
    pub squashed_checkpoints: Vec<CheckpointId>,
}

pub fn run_gc(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
    policy: &RetentionPolicy,
) -> Result<GcOutcome, SimulationError> {
    let mut outcome = GcOutcome::default();

    loop {
        if layers.checkpoints.len() <= 1 {
            break;
        }
        let total_bytes = total_retained_bytes(backend, layers)?;
        let over_count = layers.checkpoints.len() > policy.max_checkpoints;
        let over_ceiling = total_bytes > policy.storage_ceiling_bytes;
        if !over_count && !over_ceiling {
            break;
        }

        let (oldest_id, oldest_path) = layers.checkpoints[0].clone();
        squash_oldest_into_base(&oldest_path, &layers.base)?;
        backend.discard_layer(LayerId::Checkpoint(oldest_id))?;
        layers.checkpoints.remove(0);
        outcome.squashed_checkpoints.push(oldest_id);
    }

    Ok(outcome)
}

fn total_retained_bytes(
    backend: &dyn SimulationBackend,
    layers: &LayerStack,
) -> Result<u64, SimulationError> {
    let mut total = 0u64;
    for (id, _) in &layers.checkpoints {
        total += backend.layer_size_bytes(LayerId::Checkpoint(*id))?;
    }
    total += directory_size_bytes(&layers.active_write)?;
    Ok(total)
}

fn directory_size_bytes(path: &Path) -> std::io::Result<u64> {
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

fn squash_oldest_into_base(checkpoint_path: &Path, base_path: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(checkpoint_path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let file_name = entry.file_name();

        if let Some(real_name) = file_name
            .to_str()
            .and_then(|n| n.strip_prefix(WHITEOUT_PREFIX))
        {
            remove_path_if_present(&base_path.join(real_name))?;
            continue;
        }

        let dest = base_path.join(&file_name);

        if metadata.is_dir() {
            std::fs::create_dir_all(&dest)?;
            squash_oldest_into_base(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn remove_path_if_present(target: &Path) -> std::io::Result<()> {
    let result = if target.is_dir() {
        std::fs::remove_dir_all(target)
    } else {
        std::fs::remove_file(target)
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::copyup::CopyUpSimulationBackend;

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
    fn gc_is_a_no_op_when_within_both_bounds() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"small").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy::default();
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert!(outcome.squashed_checkpoints.is_empty());
        assert_eq!(stack.checkpoints.len(), 1);
    }

    #[test]
    fn gc_squashes_oldest_checkpoints_when_over_the_count_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        let mut ids = Vec::new();
        for i in 0..12 {
            std::fs::write(
                stack.active_write.join(format!("f{i}.txt")),
                format!("content {i}"),
            )
            .unwrap();
            ids.push(backend.seal_active_layer(&mut stack).unwrap());
        }
        assert_eq!(stack.checkpoints.len(), 12);

        let policy = RetentionPolicy {
            max_checkpoints: 10,
            storage_ceiling_bytes: u64::MAX,
        };
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(outcome.squashed_checkpoints, vec![ids[0], ids[1]]);
        assert_eq!(stack.checkpoints.len(), 10);
    }

    #[test]
    fn gc_never_squashes_the_newest_checkpoint_even_if_still_over_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        for i in 0..3 {
            std::fs::write(
                stack.active_write.join(format!("f{i}.txt")),
                vec![b'x'; 1000],
            )
            .unwrap();
            backend.seal_active_layer(&mut stack).unwrap();
        }

        let policy = RetentionPolicy {
            max_checkpoints: 100,
            storage_ceiling_bytes: 1,
        };
        run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(
            stack.checkpoints.len(),
            1,
            "the newest checkpoint must always survive GC"
        );
    }

    #[test]
    fn squashed_checkpoint_content_is_preserved_in_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"from checkpoint").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"second checkpoint").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: u64::MAX,
        };
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(outcome.squashed_checkpoints, vec![id1]);
        assert_eq!(
            std::fs::read_to_string(stack.base.join("a.txt")).unwrap(),
            "from checkpoint"
        );
        assert!(
            !backend.checkpoint_path(id1).exists(),
            "the squashed checkpoint's own layer must be gone"
        );
    }

    #[test]
    fn squash_overwrites_base_with_checkpoint_content_on_conflicting_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.base.join("a.txt"), b"original base content").unwrap();
        std::fs::write(stack.active_write.join("a.txt"), b"updated content").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"unrelated").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: u64::MAX,
        };
        run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(
            std::fs::read_to_string(stack.base.join("a.txt")).unwrap(),
            "updated content"
        );
    }

    #[test]
    fn squashing_a_whiteout_marker_removes_the_file_it_targets_from_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.base.join("a.txt"), b"will be deleted").unwrap();
        std::fs::write(stack.active_write.join(".wh.a.txt"), b"").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"unrelated").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: u64::MAX,
        };
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(outcome.squashed_checkpoints, vec![id1]);
        assert!(
            !stack.base.join("a.txt").exists(),
            "squashing the whiteout marker must remove the file from base, not copy the marker in"
        );
        assert!(
            !stack.base.join(".wh.a.txt").exists(),
            "the marker itself must never be copied into base"
        );
    }

    #[test]
    fn squashing_a_whiteout_marker_removes_a_directory_recursively_from_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::create_dir_all(stack.base.join("project")).unwrap();
        std::fs::write(stack.base.join("project/file.txt"), b"nested").unwrap();
        std::fs::write(stack.active_write.join(".wh.project"), b"").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"unrelated").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: u64::MAX,
        };
        run_gc(&backend, &mut stack, &policy).unwrap();

        assert!(!stack.base.join("project").exists());
    }

    #[test]
    fn squashing_a_whiteout_marker_for_a_nonexistent_base_path_is_a_harmless_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join(".wh.never_existed.txt"), b"").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"unrelated").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let policy = RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: u64::MAX,
        };
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(outcome.squashed_checkpoints.len(), 1);
    }

    #[test]
    fn gc_squashes_when_over_the_storage_ceiling_even_within_count_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        for i in 0..3 {
            std::fs::write(
                stack.active_write.join(format!("f{i}.txt")),
                vec![b'x'; 100],
            )
            .unwrap();
            backend.seal_active_layer(&mut stack).unwrap();
        }

        let policy = RetentionPolicy {
            max_checkpoints: 100,
            storage_ceiling_bytes: 50,
        };
        let outcome = run_gc(&backend, &mut stack, &policy).unwrap();

        assert_eq!(
            outcome.squashed_checkpoints.len(),
            2,
            "must squash down to exactly one checkpoint, the minimum allowed"
        );
        assert_eq!(stack.checkpoints.len(), 1);
    }
}
