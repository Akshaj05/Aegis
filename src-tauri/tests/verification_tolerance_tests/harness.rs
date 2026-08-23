//! Real, shared pipeline driver used by every test in this suite. See
//! `main.rs`'s module doc for what this deliberately does and doesn't
//! attempt to exercise.

use std::path::Path;

use chrono::Utc;
use serde_json::Value as JsonValue;

use safeshell::ai::backend::AiOutcome;
use safeshell::db::session_queries::NewSession;
use safeshell::db::Database;
use safeshell::executor;
use safeshell::parser::{parse_line, ParsedCommand};
use safeshell::policy::{Category, PolicyDecision, RiskLevel, SupportTier, Verdict};
use safeshell::rollback::{self, RollbackOutcome};
use safeshell::session::TerminalSession;
use safeshell::simulation::manager as sim_manager;
use safeshell::snapshot::backend::{LayerStack, SimulationBackend};
use safeshell::snapshot::copyup::CopyUpSimulationBackend;
use safeshell::transaction::events::CollectingEventSink;
use safeshell::transaction::{Transaction, TransactionState};
use safeshell::verification::tolerance::NondeterminismAllowlist;
use safeshell::verification::{self, VerificationResult};

pub struct PipelineOutcome {
    pub final_state: TransactionState,
    pub verification: VerificationResult,
    pub rollback_outcome: Option<RollbackOutcome>,
    pub stack: LayerStack,
}

fn parse(line: &str) -> ParsedCommand {
    parse_line(line, &std::collections::HashMap::new())
        .unwrap()
        .segments
        .into_iter()
        .next()
        .unwrap()
        .0
}

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

fn seeded_db(cmd: &str) -> Database {
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
    db.insert_command("cmd_1", "sess_1", cmd, None, &Utc::now().to_rfc3339())
        .unwrap();
    db
}

/// Runs `cmd` through the full real pipeline: simulate → policy-approved
/// low-risk fast path → snapshot seal → (`inject_drift_after_seal` gets a
/// chance to mutate the real on-disk layers here, between the snapshot
/// and execution — the one seam this harness offers callers to produce
/// genuine divergence) → execute → verify → commit, or on mismatch,
/// automatic rollback. Every step calls the crate's real production code;
/// nothing here re-implements pipeline logic.
pub fn run_pipeline(
    root: &Path,
    cmd: &str,
    inject_drift_after_seal: impl FnOnce(&CopyUpSimulationBackend, &mut LayerStack),
) -> PipelineOutcome {
    let (backend, mut stack) = fresh_stack(root);
    let db = seeded_db(cmd);
    let mut sink = CollectingEventSink::default();
    let mut session = TerminalSession::new();
    let parsed = parse(cmd);

    let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", cmd).unwrap();
    txn.record_parsed(&db, &mut sink, &parsed).unwrap();

    let decision = PolicyDecision {
        support_tier: SupportTier::Supported,
        verdict: Verdict::Allow,
        category: Some(Category::Safe),
        risk_level: Some(RiskLevel::Low),
        reason_codes: vec![],
        reasons: vec![],
    };
    txn.record_policy_decision(&db, &mut sink, &decision)
        .unwrap();
    txn.record_ai_analysis_and_enter_simulation(
        &db,
        &mut sink,
        &AiOutcome::Skipped {
            reason: "NullBackend".to_string(),
        },
    )
    .unwrap();

    let predicted = sim_manager::simulate(&backend, &stack, &mut session, &parsed).unwrap();
    txn.record_simulation_complete(&db, &mut sink, JsonValue::Null)
        .unwrap();
    txn.record_diff_ready(&db, &mut sink, false).unwrap();

    let checkpoint_id = backend.seal_active_layer(&mut stack).unwrap();
    inject_drift_after_seal(&backend, &mut stack);

    let token = txn
        .record_snapshot_sealed(
            &db,
            &mut sink,
            checkpoint_id,
            "/layers/checkpoints/test",
            1,
            Some(0),
        )
        .unwrap();

    let actual = executor::execute(&backend, &stack, &mut session, &parsed, &token).unwrap();
    txn.record_execution_complete(&db, &mut sink, JsonValue::Null)
        .unwrap();

    let allowlist = NondeterminismAllowlist::empty();
    let result = verification::verify(
        &predicted.diff,
        predicted.command_result.exit_code,
        &actual.diff,
        actual.command_result.exit_code,
        &allowlist,
    );
    txn.record_verification_result(&db, &mut sink, result.matched, result.detail().as_deref())
        .unwrap();

    let rollback_outcome = if result.matched {
        None
    } else {
        let outcome = rollback::automatic_rollback(&backend, &mut stack);
        txn.record_rollback_result(
            &db,
            &mut sink,
            outcome.success,
            outcome.failure_detail.as_deref(),
        )
        .unwrap();
        Some(outcome)
    };

    PipelineOutcome {
        final_state: txn.state(),
        verification: result,
        rollback_outcome,
        stack,
    }
}
