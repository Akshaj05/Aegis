//! Deterministic Rollback Engine — the only component that performs
//! recovery. See `docs/architecture.md` §27. Must never depend on `ai/`
//! (docs/CLAUDE.md invariant #7; checked by `tests/policy_engine_tests/main.rs`'s
//! `guarded_modules_never_reference_ai_module`). Its only real input is a
//! `CheckpointId` — this module takes that from `snapshot::backend::LayerStack`,
//! which the Snapshot Manager (`snapshot/`) owns.
//!
//! Three distinct operations, per §27.1-§27.2:
//! - [`automatic_rollback`] — triggered by verification mismatch or
//!   execution failure. Keeps the newest checkpoint; discards only the
//!   active write layer.
//! - [`undo_last_transaction`] — user-initiated, on a *committed*
//!   transaction. Discards the newest checkpoint too, landing one further
//!   back. Strictly LIFO (§23.5); `Err(NoRecoverableCheckpoint)` is the
//!   real `{ ok: false, reason: "no_recoverable_checkpoint" }` case §41
//!   documents.
//! - [`quarantine_recovery_restore_to_newest`] /
//!   [`quarantine_recovery_reset_to_base`] — the two explicit actions
//!   §27.4 offers after a `ROLLBACK_FAILED` quarantine. Named for exactly
//!   what they are rather than left as bare `restore_to` calls at the call
//!   site, since which one a quarantined session's user picks matters and
//!   should be unambiguous in the code that offers them.
//!
//! Both `automatic_rollback` and `undo_last_transaction` perform §27.3's
//! post-rollback verification (the active write layer is empty) before
//! reporting success — a restore that "succeeded" by `SimulationBackend`'s
//! own account but left an unexpected non-empty write layer is exactly
//! the kind of silent-corruption case §13.3's "rollback failure is never
//! silent" invariant exists to catch, not something to trust blindly.

use crate::snapshot::backend::{CheckpointId, LayerStack, SimulationBackend, SimulationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    pub success: bool,
    /// The checkpoint the environment now sits above, if any (`None` only
    /// when rolled all the way back to the consolidated base).
    pub restored_checkpoint_id: Option<CheckpointId>,
    pub failure_detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no recoverable checkpoint")]
pub struct NoRecoverableCheckpoint;

/// §27.2: "discard the active write layer created after the pre-execution
/// snapshot, and mount a fresh empty write layer above the sealed
/// checkpoint C_k." `C_k` is whatever the newest checkpoint already is —
/// this never removes a checkpoint, only resets the write layer above it.
pub fn automatic_rollback(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
) -> RollbackOutcome {
    let target = layers.checkpoints.last().map(|(id, _)| *id);
    restore_and_verify(backend, layers, target)
}

/// §27.2: "discard the current write layer and the topmost sealed
/// checkpoint, then create a fresh write layer above the checkpoint
/// beneath." Strictly LIFO. `Err` when there is nothing to undo at all
/// (§41's `no_recoverable_checkpoint`) — distinct from a rollback that was
/// *attempted* and failed (`Ok(RollbackOutcome { success: false, .. })`).
pub fn undo_last_transaction(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
) -> Result<RollbackOutcome, NoRecoverableCheckpoint> {
    if layers.checkpoints.is_empty() {
        return Err(NoRecoverableCheckpoint);
    }
    let target = if layers.checkpoints.len() >= 2 {
        Some(layers.checkpoints[layers.checkpoints.len() - 2].0)
    } else {
        None
    };
    Ok(restore_and_verify(backend, layers, target))
}

/// §27.4's first quarantine recovery action: "restore to the newest
/// verifiable retained checkpoint." Equivalent to [`automatic_rollback`]
/// mechanically, but named for what a quarantined session's user is
/// actually choosing, not left as an unlabeled `restore_to` call at the
/// site that offers it.
pub fn quarantine_recovery_restore_to_newest(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
) -> RollbackOutcome {
    automatic_rollback(backend, layers)
}

/// §27.4's second quarantine recovery action: "reset the environment to
/// the consolidated base."
pub fn quarantine_recovery_reset_to_base(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
) -> RollbackOutcome {
    restore_and_verify(backend, layers, None)
}

/// §30/§41's `restore_to_checkpoint` IPC command: a user-selected
/// checkpoint from this session's retained history, distinct from the two
/// named quarantine recovery targets above. Callers (the orchestrator,
/// `orchestrator/mod.rs`) validate `checkpoint_id` is a member of the
/// caller's own `LayerStack.checkpoints` before calling this — unknown or
/// garbage-collected ids are refused there, per §30's constraint, not
/// here (this function has no way to distinguish "never existed" from
/// "already discarded" once given a bare id; the caller's live stack membership
/// check is what actually enforces the constraint).
pub fn restore_to_checkpoint(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
    checkpoint_id: CheckpointId,
) -> RollbackOutcome {
    restore_and_verify(backend, layers, Some(checkpoint_id))
}

fn restore_and_verify(
    backend: &dyn SimulationBackend,
    layers: &mut LayerStack,
    target: Option<CheckpointId>,
) -> RollbackOutcome {
    match backend.restore_to(layers, target) {
        Ok(()) => match verify_active_write_is_empty(layers) {
            Ok(()) => RollbackOutcome {
                success: true,
                restored_checkpoint_id: target,
                failure_detail: None,
            },
            Err(detail) => RollbackOutcome {
                success: false,
                restored_checkpoint_id: target,
                failure_detail: Some(detail),
            },
        },
        Err(e) => RollbackOutcome {
            success: false,
            restored_checkpoint_id: target,
            failure_detail: Some(describe(e)),
        },
    }
}

fn verify_active_write_is_empty(layers: &LayerStack) -> Result<(), String> {
    if !layers.active_write.is_dir() {
        return Err(format!(
            "active write layer missing after restore: {}",
            layers.active_write.display()
        ));
    }
    let has_entries = std::fs::read_dir(&layers.active_write)
        .map_err(|e| e.to_string())?
        .next()
        .is_some();
    if has_entries {
        return Err("active write layer is not empty after restore".to_string());
    }
    Ok(())
}

fn describe(e: SimulationError) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::copyup::CopyUpSimulationBackend;
    use std::path::Path;

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
    fn automatic_rollback_discards_only_the_active_write_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"committed").unwrap();
        let checkpoint_id = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(
            stack.active_write.join("partial.txt"),
            b"mid-execution garbage",
        )
        .unwrap();

        let outcome = automatic_rollback(&backend, &mut stack);

        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, Some(checkpoint_id));
        assert_eq!(
            stack.checkpoints.len(),
            1,
            "the checkpoint itself must survive automatic rollback"
        );
        assert!(!stack.active_write.join("partial.txt").exists());
    }

    #[test]
    fn undo_last_transaction_removes_the_newest_checkpoint_and_lands_on_the_one_beneath() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"2").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let outcome = undo_last_transaction(&backend, &mut stack).unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, Some(id1));
        assert_eq!(stack.checkpoints, vec![(id1, backend.checkpoint_path(id1))]);
    }

    #[test]
    fn undo_last_transaction_with_only_one_checkpoint_lands_on_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let outcome = undo_last_transaction(&backend, &mut stack).unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, None);
        assert!(stack.checkpoints.is_empty());
    }

    #[test]
    fn undo_last_transaction_with_no_checkpoints_reports_no_recoverable_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        let result = undo_last_transaction(&backend, &mut stack);
        assert_eq!(result, Err(NoRecoverableCheckpoint));
    }

    #[test]
    fn undo_last_transaction_is_strictly_lifo_across_repeated_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        for i in 0..3 {
            std::fs::write(stack.active_write.join(format!("f{i}.txt")), i.to_string()).unwrap();
            backend.seal_active_layer(&mut stack).unwrap();
        }
        assert_eq!(stack.checkpoints.len(), 3);

        undo_last_transaction(&backend, &mut stack).unwrap();
        assert_eq!(stack.checkpoints.len(), 2);
        undo_last_transaction(&backend, &mut stack).unwrap();
        assert_eq!(stack.checkpoints.len(), 1);
        undo_last_transaction(&backend, &mut stack).unwrap();
        assert_eq!(stack.checkpoints.len(), 0);
        assert_eq!(
            undo_last_transaction(&backend, &mut stack),
            Err(NoRecoverableCheckpoint)
        );
    }

    #[test]
    fn quarantine_recovery_reset_to_base_discards_every_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        for i in 0..3 {
            std::fs::write(stack.active_write.join(format!("f{i}.txt")), i.to_string()).unwrap();
            backend.seal_active_layer(&mut stack).unwrap();
        }

        let outcome = quarantine_recovery_reset_to_base(&backend, &mut stack);

        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, None);
        assert!(stack.checkpoints.is_empty());
    }

    #[test]
    fn quarantine_recovery_restore_to_newest_matches_automatic_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();

        let outcome = quarantine_recovery_restore_to_newest(&backend, &mut stack);
        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, Some(id1));
    }

    #[test]
    fn restore_to_checkpoint_restores_an_arbitrary_retained_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        let id1 = backend.seal_active_layer(&mut stack).unwrap();
        std::fs::write(stack.active_write.join("b.txt"), b"2").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let outcome = restore_to_checkpoint(&backend, &mut stack, id1);
        assert!(outcome.success);
        assert_eq!(outcome.restored_checkpoint_id, Some(id1));
        assert_eq!(stack.checkpoints, vec![(id1, backend.checkpoint_path(id1))]);
    }

    #[test]
    fn a_failed_restore_reports_failure_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"1").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();

        let bogus = CheckpointId(ulid::Ulid::new());
        let outcome = restore_and_verify(&backend, &mut stack, Some(bogus));
        assert!(!outcome.success);
        assert!(outcome.failure_detail.is_some());
    }
}
