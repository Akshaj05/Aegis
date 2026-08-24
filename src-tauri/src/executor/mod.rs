//! Secure Executor: runs the same handler code path as simulation, against
//! the persistent active write layer, reachable only via an
//! `ApprovedExecutionToken`. See `docs/architecture.md` §24.
//!
//! **Shares its shape with `simulation::manager::simulate`
//! deliberately** (docs/CLAUDE.md invariant #20 / §19.3): same
//! `handlers::dispatch` call, same `simulation::diff::compute` diff
//! computation, same `LayeredResolver`. The only real difference is the
//! write target — `WriteTarget::ActiveWrite` (persistent) instead of
//! `WriteTarget::Transient` (discarded via an RAII guard on every exit
//! path) — and the token check at the top, which simulation has no
//! equivalent of because simulation never touches persistent state at
//! all.
//!
//! Must never depend on `ai/` (docs/CLAUDE.md invariant #7) — enforced by
//! `tests/policy_engine_tests`'s dependency scan.

use crate::handlers::{self, CommandResult};
use crate::parser::ParsedCommand;
use crate::session::TerminalSession;
use crate::simulation::diff::{self, SimulationDiff};
use crate::simulation::resolver::LayeredResolver;
use crate::snapshot::backend::{LayerStack, SimulationBackend, SimulationError, WriteTarget};
use crate::transaction::ApprovedExecutionToken;

pub struct ExecutionOutcome {
    pub command_result: CommandResult,
    pub diff: SimulationDiff,
}

/// §24: "The Executor validates that the checkpoint id resolves to a
/// sealed layer before doing anything. There is no other entry point."
/// `token` can only have been constructed on the real
/// `SNAPSHOTTING -> EXECUTING` edge (`ApprovedExecutionToken`'s
/// `pub(super)` constructor), but this still checks that its checkpoint
/// id names a layer actually present in `layers` — a token from a
/// different session's layer stack, or a stack that has since been
/// GC'd/rolled back out from under it, must not be treated as
/// authorization to write here.
pub fn execute(
    backend: &dyn SimulationBackend,
    layers: &LayerStack,
    session: &mut TerminalSession,
    parsed: &ParsedCommand,
    token: &ApprovedExecutionToken,
) -> Result<ExecutionOutcome, SimulationError> {
    let sealed = layers
        .checkpoints
        .iter()
        .any(|(id, _)| *id == token.checkpoint_id());
    if !sealed {
        return Err(SimulationError::UnknownCheckpoint);
    }

    let view = backend.mount_view(layers, WriteTarget::ActiveWrite)?;
    let resolver = LayeredResolver::from_mounted_view(&view)?;

    let command_result = handlers::dispatch(
        &parsed.name,
        &parsed.args,
        &parsed.redirections,
        session,
        &resolver,
    );

    let active_write_path = view
        .layers
        .first()
        .expect("mount_view always returns at least one layer")
        .clone();
    let diff = diff::compute(&active_write_path, &view)?;

    Ok(ExecutionOutcome {
        command_result,
        diff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_queries::NewSession;
    use crate::db::Database;
    use crate::parser::parse_line;
    use crate::policy::{Category, PolicyDecision, RiskLevel, SupportTier, Verdict};
    use crate::snapshot::backend::CheckpointId;
    use crate::snapshot::copyup::CopyUpSimulationBackend;
    use crate::transaction::events::CollectingEventSink;
    use crate::transaction::manager::Transaction;
    use chrono::Utc;
    use serde_json::Value as JsonValue;
    use std::collections::HashMap;
    use ulid::Ulid;

    fn fresh_stack(root: &std::path::Path) -> (CopyUpSimulationBackend, LayerStack) {
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

    fn parse(line: &str) -> ParsedCommand {
        parse_line(line, &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0
    }

    fn seeded_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        db.insert_session(&NewSession {
            id: "sess_1".into(),
            created_at: Utc::now().to_rfc3339(),
            layer_root_path: None,
            sandbox_backend: None,
            simulation_backend: None,
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();
        db.insert_command(
            "cmd_1",
            "sess_1",
            "mkdir project",
            None,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        db
    }

    /// Drives a real `Transaction` through the real state machine up to
    /// `SNAPSHOTTING -> EXECUTING`, sealing `checkpoint_id` (already
    /// sealed for real on `stack` by the caller) along the way — the only
    /// way this crate allows an `ApprovedExecutionToken` to come into
    /// existence (docs/CLAUDE.md invariant #11). No bypass, no test-only
    /// constructor.
    fn approved_token_for(db: &Database, checkpoint_id: CheckpointId) -> ApprovedExecutionToken {
        let mut sink = CollectingEventSink::default();
        let cmd = parse("mkdir project");
        let mut txn =
            Transaction::begin(db, &mut sink, "sess_1", "cmd_1", "mkdir project").unwrap();
        txn.record_parsed(db, &mut sink, &cmd).unwrap();
        let decision = PolicyDecision {
            support_tier: SupportTier::Supported,
            verdict: Verdict::Allow,
            category: Some(Category::Safe),
            risk_level: Some(RiskLevel::Low),
            reason_codes: vec![],
            reasons: vec![],
        };
        txn.record_policy_decision(db, &mut sink, &decision)
            .unwrap();
        txn.skip_ai_analysis(db, &mut sink, "NullBackend").unwrap();
        txn.record_simulation_complete(db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_diff_ready(db, &mut sink, false).unwrap();
        txn.record_snapshot_sealed(
            db,
            &mut sink,
            checkpoint_id,
            "/layers/checkpoints/test",
            1,
            Some(0),
        )
        .unwrap()
    }

    #[test]
    fn executing_writes_persist_to_the_active_write_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("seed.txt"), b"seed").unwrap();
        let checkpoint_id = backend.seal_active_layer(&mut stack).unwrap();
        let db = seeded_db();
        let token = approved_token_for(&db, checkpoint_id);
        let mut session = TerminalSession::new();
        let cmd = parse("mkdir project");

        let outcome = execute(&backend, &stack, &mut session, &cmd, &token).unwrap();

        assert_eq!(outcome.command_result.exit_code, 0);
        assert_eq!(
            outcome.diff.directories_created,
            vec!["project".to_string()]
        );
        assert!(
            stack.active_write.join("project").exists(),
            "unlike simulation, execution must leave its write in the persistent active write layer"
        );
    }

    #[test]
    fn a_token_naming_a_checkpoint_absent_from_this_stack_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        let unrelated_checkpoint = CheckpointId(Ulid::new());
        let db = seeded_db();
        let token = approved_token_for(&db, unrelated_checkpoint);
        let mut session = TerminalSession::new();
        let cmd = parse("mkdir project");

        let result = execute(&backend, &stack, &mut session, &cmd, &token);
        assert!(matches!(result, Err(SimulationError::UnknownCheckpoint)));
        assert!(
            !stack.active_write.join("project").exists(),
            "a refused token must not have run the handler at all"
        );
    }

    #[test]
    fn execution_diff_reflects_what_actually_changed_relative_to_sealed_checkpoints() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("existing.txt"), b"already here").unwrap();
        let checkpoint_id = backend.seal_active_layer(&mut stack).unwrap();
        let db = seeded_db();
        let token = approved_token_for(&db, checkpoint_id);
        let mut session = TerminalSession::new();
        let cmd = parse("touch existing.txt");

        let outcome = execute(&backend, &stack, &mut session, &cmd, &token).unwrap();
        assert_eq!(outcome.command_result.exit_code, 0);
        assert!(
            outcome.diff.files_created.is_empty() && outcome.diff.files_modified.is_empty(),
            "touch on an existing, unchanged file must report no change, same as simulation"
        );
    }
}
