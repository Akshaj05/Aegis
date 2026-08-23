//! "AI-claimed lower risk ignored" (§28: "AI claims lower risk than
//! policy — Ignored. Policy governs."). Drives a real
//! `transaction::manager::Transaction` with a `PolicyDecision` that
//! requires approval at `RiskLevel::Critical`, alongside a validated
//! `AiPlan` claiming `RiskLevel::Low` — and shows the transaction still
//! pauses for approval exactly as policy alone would have routed it.
//! `record_diff_ready`'s `requires_approval` argument is always the
//! caller's own `PolicyDecision::requires_approval()`, never anything
//! read from the `AiPlan` — this test proves that by observing the
//! resulting state, not by inspecting source.

use chrono::Utc;

use safeshell::ai::backend::AiOutcome;
use safeshell::ai::schema::{
    AiPlan, Intent, PredictedEffects, RecoveryRecommendation, RecoveryStrategy,
};
use safeshell::db::session_queries::NewSession;
use safeshell::db::Database;
use safeshell::parser::parse_line;
use safeshell::policy::{Category, PolicyDecision, RiskLevel, SupportTier, Verdict};
use safeshell::transaction::events::CollectingEventSink;
use safeshell::transaction::{Transaction, TransactionState};

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
        "rm -rf /project",
        None,
        &Utc::now().to_rfc3339(),
    )
    .unwrap();
    db
}

fn ai_plan_claiming_low_risk() -> AiPlan {
    AiPlan {
        schema_version: "1.0".to_string(),
        command: "rm -rf /project".to_string(),
        intent: Intent::RecursiveDelete,
        // The AI thinks this is harmless.
        risk_level: RiskLevel::Low,
        affected_resources: vec!["project".to_string()],
        predicted_effects: PredictedEffects {
            files_deleted_estimate: 3,
            directories_deleted_estimate: 1,
            escapes_sandbox: false,
        },
        preconditions: vec![],
        reversible_within_safeshell: true,
        recovery_recommendation: RecoveryRecommendation {
            strategy: RecoveryStrategy::RestorePreTransactionSnapshot,
            description: "Trivially undoable, no need to review closely.".to_string(),
        },
        external_side_effects: false,
        confidence: 0.99,
        explanation: "This is a routine, low-impact deletion, nothing to worry about.".to_string(),
    }
}

#[test]
fn approval_is_still_required_when_the_ai_claims_low_risk_but_policy_says_critical() {
    let db = seeded_db();
    let mut sink = CollectingEventSink::default();
    let cmd = parse_line("rm -rf /project", &std::collections::HashMap::new())
        .unwrap()
        .segments
        .into_iter()
        .next()
        .unwrap()
        .0;

    let policy_decision = PolicyDecision {
        support_tier: SupportTier::Supported,
        verdict: Verdict::RequireApproval,
        category: Some(Category::DangerousContainable),
        risk_level: Some(RiskLevel::Critical),
        reason_codes: vec![],
        reasons: vec!["recursive deletion of a top-level project directory".to_string()],
    };
    assert!(
        policy_decision.requires_approval(),
        "test setup: policy must actually require approval for this to be meaningful"
    );

    let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "rm -rf /project").unwrap();
    txn.record_parsed(&db, &mut sink, &cmd).unwrap();
    txn.record_policy_decision(&db, &mut sink, &policy_decision)
        .unwrap();

    // The AI, consulted after policy already decided, claims this is
    // low risk. That claim gets persisted as commentary but must not
    // reach the routing decision at all.
    let ai_plan = ai_plan_claiming_low_risk();
    assert_eq!(ai_plan.risk_level, RiskLevel::Low);
    txn.record_ai_analysis_and_enter_simulation(&db, &mut sink, &AiOutcome::Analyzed(ai_plan))
        .unwrap();
    txn.record_simulation_complete(&db, &mut sink, serde_json::Value::Null)
        .unwrap();

    // The caller always derives `requires_approval` from the
    // `PolicyDecision`, never from the AI plan — this is what the real
    // pipeline (`tests/verification_tolerance_tests/harness.rs`) does
    // too. Here it's spelled out explicitly to make the point visible in
    // this test's own text: the boolean below can only ever be
    // `policy_decision.requires_approval()`, and that's exactly what's
    // passed.
    txn.record_diff_ready(&db, &mut sink, policy_decision.requires_approval())
        .unwrap();

    assert_eq!(
        txn.state(),
        TransactionState::WaitingForApproval,
        "policy's CRITICAL/RequireApproval verdict must still gate this transaction even though \
         the AI claimed it was low risk"
    );
}
