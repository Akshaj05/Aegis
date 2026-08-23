//! `Transaction` — one command's journey through §13's state machine.
//! Every method here corresponds to exactly one legal edge in
//! `state::TransactionState::legal_next_states`; there is no other way to
//! change a `Transaction`'s state anywhere in this crate (§29.1: "Every
//! state transition... emits an event, unconditionally, before the next
//! stage begins").
//!
//! **Scope of this pass**: this module's methods accept the *outcome* of
//! each pipeline stage as a parameter — a caller supplies "here is the
//! `PolicyDecision`," "here is whether the AI was skipped," "here is the
//! sealed `CheckpointId`," "here is the real `SimulationDiff` from
//! `executor::execute`" — and this module's job is entirely about
//! validating the transition, persisting it, and emitting the event, not
//! about producing that outcome. That's a deliberate division matching
//! the Build order's own phase boundaries: this is "Transaction manager +
//! events," not "Simulation + diff," "Snapshot + rollback,"
//! "Verification," or "AI planner." As of Build order phase 8, every
//! stage but the AI planner (`ai/`, phase 9) supplies a real outcome —
//! see `tests/verification_tolerance_tests/harness.rs` for the full
//! pipeline driven end to end through these same methods. Nothing here
//! needed to change shape to accommodate any of that, because the methods
//! already took exactly the domain data those phases would produce.
//!
//! **A state-machine gap this module had to resolve, not invent**: §13.1's
//! state list has no state for `Verdict::RejectUnsupported`
//! (`policy::types`) — only `DENIED`, `REJECTED`, and `FAILED` exist as
//! terminal non-success states. Mapping `RejectUnsupported` to `DENIED`
//! would directly violate docs/CLAUDE.md invariant #3 ("UNSUPPORTED ≠
//! DENIED... never conflate"). `FAILED`'s own definition ("pipeline
//! failure before execution") fits "not implemented" reasonably, and
//! staying distinct from `Denied` is the invariant that actually matters
//! here — so `record_policy_rejected_unsupported` targets `Failed`, with
//! its own distinct audit `event_type` (`policy_rejected_unsupported`, not
//! `policy_denied`) so the audit trail still tells the two apart even
//! though the state value is shared with other, unrelated `FAILED`
//! causes.

use chrono::Utc;
use serde_json::Value as JsonValue;
use ulid::Ulid;

use crate::db::Database;
use crate::parser::ParsedCommand;
use crate::policy::{Category, PolicyDecision, RiskLevel, Verdict};
use crate::snapshot::backend::CheckpointId;
use crate::transaction::events::{EventSink, EventStatus, TransactionEvent};
use crate::transaction::state::{self, TransactionState};
use crate::transaction::token::ApprovedExecutionToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(Ulid);

impl TransactionId {
    pub fn new() -> Self {
        TransactionId(Ulid::new())
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "txn_{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error(transparent)]
    IllegalTransition(#[from] state::IllegalTransitionError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// §27.4: a `ROLLBACK_FAILED` session accepts no further commands
    /// until one of the two explicit quarantine recovery actions
    /// (`rollback::quarantine_recovery_restore_to_newest`/
    /// `..._reset_to_base`) runs.
    #[error("session {session_id} is quarantined following a rollback failure — no further commands are accepted until it is explicitly recovered")]
    SessionQuarantined { session_id: String },
}

pub struct Transaction {
    pub id: TransactionId,
    pub session_id: String,
    pub command_id: String,
    pub raw_command: String,
    state: TransactionState,
    sequence: u64,
    category: Option<Category>,
    policy_risk_level: Option<RiskLevel>,
}

impl Transaction {
    /// `RECEIVED`: "line submitted, transaction created" (§13.1). Inserts
    /// the `transactions` row and emits the first event.
    ///
    /// Refuses outright — before inserting anything — if the session is
    /// quarantined (§27.4). This is deliberately checked here rather than
    /// left to fail some other way downstream: a quarantined session must
    /// reject *every* command, including ones that would otherwise be
    /// entirely safe, until an explicit recovery action runs.
    pub fn begin(
        db: &Database,
        sink: &mut dyn EventSink,
        session_id: &str,
        command_id: &str,
        raw_command: &str,
    ) -> Result<Self, TransactionError> {
        if db.get_session_status(session_id)?.as_deref() == Some("quarantined") {
            return Err(TransactionError::SessionQuarantined {
                session_id: session_id.to_string(),
            });
        }

        let id = TransactionId::new();
        db.insert_transaction(
            &id.to_string(),
            command_id,
            session_id,
            &Utc::now().to_rfc3339(),
        )?;

        let mut txn = Transaction {
            id,
            session_id: session_id.to_string(),
            command_id: command_id.to_string(),
            raw_command: raw_command.to_string(),
            state: TransactionState::Received,
            sequence: 0,
            category: None,
            policy_risk_level: None,
        };
        txn.emit(
            db,
            sink,
            EventStatus::Started,
            "line submitted",
            JsonValue::Null,
        )?;
        Ok(txn)
    }

    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// Validates and applies `from -> to`, persists the row's terminal
    /// state if `to` is terminal, and emits the event. This is the
    /// **only** place `self.state` is ever assigned — every public method
    /// below goes through this.
    #[allow(clippy::too_many_arguments)]
    fn advance(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        to: TransactionState,
        status: EventStatus,
        message: &str,
        metrics: JsonValue,
    ) -> Result<(), TransactionError> {
        if let Err(e) = state::transition(self.state, to) {
            // docs/CLAUDE.md: "an attempted illegal transition is a
            // panic-level invariant violation in debug builds and a
            // FAILED + loud audit event in release builds." `debug_assert!`
            // panics here in debug (including `cargo test`'s default
            // profile — exercised by this module's
            // `#[should_panic]` test) and compiles to nothing in release,
            // where execution falls through to the forced-FAILED path
            // below instead. That release-mode fallback path is not
            // exercised by this test suite (it needs a `--release` build
            // with debug-assertions off, which this dev environment's
            // default `cargo test` never produces) — stated plainly
            // rather than silently assumed correct.
            debug_assert!(false, "illegal transaction state transition attempted: {e} — this is a logic defect, not a runtime condition");
            self.state = TransactionState::Failed;
            let _ = db.insert_audit_row(
                Some(&self.id.to_string()),
                Some(&self.session_id),
                "illegal_transition_forced_failed",
                &format!(r#"{{"from":"{}","to":"{}"}}"#, e.from, e.to),
                &Utc::now().to_rfc3339(),
            );
            return Err(TransactionError::IllegalTransition(e));
        }

        self.state = to;
        self.emit(db, sink, status, message, metrics)?;

        if to.is_terminal() {
            db.update_transaction_final_state(
                &self.id.to_string(),
                &to.to_string(),
                &Utc::now().to_rfc3339(),
            )?;
        }
        Ok(())
    }

    fn emit(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        status: EventStatus,
        message: &str,
        metrics: JsonValue,
    ) -> Result<(), TransactionError> {
        self.sequence += 1;
        let event = TransactionEvent {
            transaction_id: self.id,
            session_id: self.session_id.clone(),
            command: self.raw_command.clone(),
            stage: self.state,
            status,
            timestamp: Utc::now(),
            duration_ms: None,
            category: self.category,
            policy_risk_level: self.policy_risk_level,
            metrics,
            message: message.to_string(),
            sequence: self.sequence,
        };
        db.insert_transaction_event(
            &event.transaction_id.to_string(),
            &event.stage.to_string(),
            event.status.as_str(),
            &event.timestamp.to_rfc3339(),
            event.duration_ms.map(|d| d as i64),
            Some(&event.metrics.to_string()),
            &event.message,
            event.sequence as i64,
        )?;
        sink.emit(&event);
        Ok(())
    }

    fn write_audit(
        &self,
        db: &Database,
        event_type: &str,
        payload: &JsonValue,
    ) -> Result<(), TransactionError> {
        db.insert_audit_row(
            Some(&self.id.to_string()),
            Some(&self.session_id),
            event_type,
            &payload.to_string(),
            &Utc::now().to_rfc3339(),
        )?;
        Ok(())
    }

    // --- RECEIVED -> {PARSED, FAILED} ---

    pub fn record_parsed(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        parsed: &ParsedCommand,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Parsed,
            EventStatus::Completed,
            &format!("parsed as `{}`", parsed.name),
            JsonValue::Null,
        )
    }

    pub fn record_parse_failure(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        error_message: &str,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Failed,
            EventStatus::Failed,
            error_message,
            JsonValue::Null,
        )
    }

    // --- PARSED -> POLICY_CHECK -> {DENIED, FAILED (unsupported), AI_ANALYSIS} ---

    /// Enters `POLICY_CHECK` and immediately routes based on `decision`,
    /// per §20.1's evaluation order having already run by the time this
    /// is called (the Policy Engine itself is stateless and doesn't need
    /// the transaction's state machine to run — this method just records
    /// what it already decided).
    pub fn record_policy_decision(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        decision: &PolicyDecision,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::PolicyCheck,
            EventStatus::Completed,
            "policy evaluated",
            JsonValue::Null,
        )?;

        self.category = decision.category;
        self.policy_risk_level = decision.risk_level;

        let reason_codes: Vec<String> = decision
            .reason_codes
            .iter()
            .map(|r| r.to_string())
            .collect();
        let reason_codes_json =
            serde_json::to_string(&reason_codes).unwrap_or_else(|_| "[]".to_string());
        // `update_transaction_policy_fields` (`db::transaction_queries`)
        // existed since Build order phase 5 and was never actually called
        // here — a real, silent gap found and closed while wiring the
        // adjacent `update_transaction_ai_fields` gap below for phase 9's
        // AI data. `Category`/`SupportTier` gained `Display` impls for
        // this (`policy::types`).
        db.update_transaction_policy_fields(
            &self.id.to_string(),
            decision.category.map(|c| c.to_string()).as_deref(),
            &decision.support_tier.to_string(),
            decision.risk_level.map(|r| r.to_string()).as_deref(),
            &reason_codes_json,
            decision.requires_approval(),
        )?;

        match decision.verdict {
            Verdict::Deny => {
                self.write_audit(
                    db,
                    "policy_denied",
                    &serde_json::json!({"reason_codes": reason_codes, "reasons": decision.reasons}),
                )?;
                self.advance(
                    db,
                    sink,
                    TransactionState::Denied,
                    EventStatus::Completed,
                    &decision.reasons.join("; "),
                    serde_json::json!({"reason_codes": reason_codes}),
                )
            }
            Verdict::RejectUnsupported => {
                // See this module's doc comment for why FAILED, not
                // DENIED — and why the audit event_type is deliberately
                // different from `policy_denied` regardless.
                self.write_audit(
                    db,
                    "policy_rejected_unsupported",
                    &serde_json::json!({"reasons": decision.reasons}),
                )?;
                self.advance(
                    db,
                    sink,
                    TransactionState::Failed,
                    EventStatus::Completed,
                    &decision.reasons.join("; "),
                    JsonValue::Null,
                )
            }
            Verdict::Allow | Verdict::RequireApproval => Ok(()),
        }
    }

    // --- POLICY_CHECK -> AI_ANALYSIS -> SIMULATING (always, per §13.2) ---

    /// Both edges fire unconditionally once policy allows proceeding —
    /// "AI_ANALYSIS -> SIMULATING (always; AI failure sets flag, never
    /// blocks)" (§13.2), which is exactly why this takes an
    /// [`AiOutcome`] rather than a `Result`: §21.9's fallback ("proceed on
    /// deterministic policy alone") isn't a special case this method
    /// handles, it's the *only* thing `AiOutcome::Skipped` can mean by
    /// construction (see that type's doc comment).
    ///
    /// As of Build order phase 9: `update_transaction_ai_fields`
    /// (`db::transaction_queries`, existed since phase 5) is now actually
    /// called — it was as silently unwired as
    /// `update_transaction_policy_fields` was until this same pass fixed
    /// both. A real `AiPlan` also gets persisted to `ai_plans`
    /// (`db::ai_queries`) and checked for the one divergence that's
    /// meaningful at this point in the pipeline: `escapes_sandbox`
    /// (`ai::divergence::detect_escapes_sandbox_divergence`) — a finding
    /// becomes an `ai_divergence` audit event, never anything that alters
    /// routing (§28).
    pub fn record_ai_analysis_and_enter_simulation(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        ai_outcome: &crate::ai::backend::AiOutcome,
    ) -> Result<(), TransactionError> {
        use crate::ai::backend::AiOutcome;

        let (ai_skipped, ai_skipped_reason, ai_plan) = match ai_outcome {
            AiOutcome::Analyzed(plan) => (false, None, Some(plan)),
            AiOutcome::Skipped { reason } => (true, Some(reason.as_str()), None),
        };

        let ai_risk_level = ai_plan.map(|p| p.risk_level.to_string());
        db.update_transaction_ai_fields(
            &self.id.to_string(),
            ai_risk_level.as_deref(),
            ai_skipped,
            ai_skipped_reason,
        )?;

        if let Some(plan) = ai_plan {
            let divergence = crate::ai::divergence::detect_escapes_sandbox_divergence(plan);
            let divergence_json = divergence.as_ref().map(|d| {
                serde_json::json!({
                    "field": format!("{:?}", d.field),
                    "ai_claimed": d.ai_claimed,
                    "ground_truth": d.ground_truth,
                })
                .to_string()
            });

            // `serde_json::to_value` renders the closed enum in its wire
            // form (e.g. `"directory_create"`, not the Rust `Debug`
            // spelling `DirectoryCreate`) — the same representation a
            // real `AiPlan` arrived over the wire as.
            let intent_str = serde_json::to_value(plan.intent)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string));
            db.insert_ai_plan(&crate::db::ai_queries::NewAiPlan {
                id: &format!("aiplan_{}", Ulid::new()),
                transaction_id: &self.id.to_string(),
                raw_response: None,
                validated: true,
                schema_version: Some(&plan.schema_version),
                intent: intent_str.as_deref(),
                risk_level: Some(&plan.risk_level.to_string()),
                confidence: Some(plan.confidence),
                recovery_recommendation_json: serde_json::to_string(&plan.recovery_recommendation)
                    .ok()
                    .as_deref(),
                explanation: Some(&plan.explanation),
                divergence_json: divergence_json.as_deref(),
            })?;

            if let Some(d) = &divergence {
                self.write_audit(
                    db,
                    "ai_divergence",
                    &serde_json::json!({
                        "field": format!("{:?}", d.field),
                        "ai_claimed": d.ai_claimed,
                        "ground_truth": d.ground_truth,
                    }),
                )?;
            }
        }

        let message = if ai_skipped {
            ai_skipped_reason.unwrap_or(
                "AI analysis unavailable — proceeding on deterministic policy assessment",
            )
        } else {
            "AI analysis complete"
        };
        self.advance(
            db,
            sink,
            TransactionState::AiAnalysis,
            EventStatus::Completed,
            message,
            serde_json::json!({"ai_skipped": ai_skipped}),
        )?;
        self.advance(
            db,
            sink,
            TransactionState::Simulating,
            EventStatus::Started,
            "running simulation pass in disposable layer",
            JsonValue::Null,
        )
    }

    /// Convenience wrapper around
    /// [`record_ai_analysis_and_enter_simulation`](Self::record_ai_analysis_and_enter_simulation)
    /// for the common "AI wasn't consulted at all" case (disabled,
    /// `NullBackend`, or a caller that hasn't wired a backend in yet).
    /// Exists so that callers outside `transaction/` — concretely,
    /// `executor/`'s own tests, which need to drive a `Transaction` up to
    /// `EXECUTING` to obtain a real `ApprovedExecutionToken` — never need
    /// to reference `crate::ai::backend::AiOutcome` themselves just to
    /// pass the trivial no-AI case through. `executor/` must never depend
    /// on `ai/` at all (docs/CLAUDE.md invariant #7, enforced by
    /// `tests/policy_engine_tests`'s dependency scan) — this method is
    /// what keeps that true while still letting its tests reach a state
    /// only obtainable by passing through `AI_ANALYSIS`.
    pub fn skip_ai_analysis(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        reason: &str,
    ) -> Result<(), TransactionError> {
        self.record_ai_analysis_and_enter_simulation(
            db,
            sink,
            &crate::ai::backend::AiOutcome::Skipped {
                reason: reason.to_string(),
            },
        )
    }

    // --- SIMULATING -> {DIFF_READY, FAILED} ---

    pub fn record_simulation_complete(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        metrics: JsonValue,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::DiffReady,
            EventStatus::Completed,
            "predicted diff computed",
            metrics,
        )
    }

    pub fn record_simulation_failure(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        error_message: &str,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Failed,
            EventStatus::Failed,
            error_message,
            JsonValue::Null,
        )
    }

    // --- DIFF_READY -> {WAITING_FOR_APPROVAL, SNAPSHOTTING} ---

    /// §12's routing: "Policy final decision (recomputed): LOW -> proceed;
    /// MED/HIGH/CRITICAL -> WAITING_FOR_APPROVAL." `requires_approval` is
    /// the caller's already-recomputed answer (§20.6's pre-execution
    /// re-validation), not decided by this method.
    pub fn record_diff_ready(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        requires_approval: bool,
    ) -> Result<(), TransactionError> {
        if requires_approval {
            self.advance(
                db,
                sink,
                TransactionState::WaitingForApproval,
                EventStatus::Started,
                "awaiting user approval",
                JsonValue::Null,
            )
        } else {
            self.advance(
                db,
                sink,
                TransactionState::Snapshotting,
                EventStatus::Started,
                "risk is low; proceeding without an approval pause",
                JsonValue::Null,
            )
        }
    }

    // --- WAITING_FOR_APPROVAL -> {SNAPSHOTTING, REJECTED, FAILED} ---

    pub fn approve(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
    ) -> Result<(), TransactionError> {
        db.update_transaction_approval(&self.id.to_string(), true, &Utc::now().to_rfc3339())?;
        self.write_audit(db, "user_approved", &JsonValue::Null)?;
        self.advance(
            db,
            sink,
            TransactionState::Snapshotting,
            EventStatus::Started,
            "user approved",
            JsonValue::Null,
        )
    }

    /// §13.3: "REJECTED never modifies persistent state" — structurally
    /// true because this is the only path to `Rejected`, and it's only
    /// reachable from here, strictly before `SNAPSHOTTING` (the first
    /// state that writes anything persistent).
    pub fn reject(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
    ) -> Result<(), TransactionError> {
        db.update_transaction_approval(&self.id.to_string(), false, &Utc::now().to_rfc3339())?;
        self.write_audit(db, "user_rejected", &JsonValue::Null)?;
        self.advance(
            db,
            sink,
            TransactionState::Rejected,
            EventStatus::Completed,
            "user rejected — no persistent state was modified",
            JsonValue::Null,
        )
    }

    /// §13.2: "FAILED on session teardown/timeout." §28: "Absence of
    /// approval is never treated as approval."
    pub fn record_approval_timeout(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Failed,
            EventStatus::Failed,
            "approval timed out or the session was torn down",
            JsonValue::Null,
        )
    }

    // --- SNAPSHOTTING -> {EXECUTING, FAILED} ---

    /// The **only** place in this crate an [`ApprovedExecutionToken`] can
    /// be constructed (§13.3, §24) — enforced by `ApprovedExecutionToken::new`
    /// being `pub(super)`, callable only from within `transaction/`.
    ///
    /// Inserts the `snapshots` row **before** setting
    /// `transactions.pre_execution_checkpoint_id` (a foreign key into
    /// `snapshots(id)`) — this exact ordering was gotten wrong once
    /// already: an earlier version of this method set the foreign key
    /// first, with no `snapshots` row existing yet at all, and hit a real
    /// `FOREIGN KEY constraint failed` error in its own tests. Now that
    /// `db::snapshot_queries` exists (Build order phase 7), the row can
    /// actually be inserted here, in the right order, closing the gap
    /// that method's doc comment used to describe as deferred.
    #[allow(clippy::too_many_arguments)]
    pub fn record_snapshot_sealed(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        checkpoint_id: CheckpointId,
        layer_path: &str,
        layer_ordinal: i64,
        size_bytes: Option<i64>,
    ) -> Result<ApprovedExecutionToken, TransactionError> {
        db.insert_snapshot(
            &checkpoint_id.to_string(),
            &self.session_id,
            Some(&self.id.to_string()),
            layer_path,
            layer_ordinal,
            size_bytes,
            &Utc::now().to_rfc3339(),
        )?;
        db.update_transaction_checkpoint(&self.id.to_string(), &checkpoint_id.to_string())?;

        self.advance(
            db,
            sink,
            TransactionState::Executing,
            EventStatus::Started,
            &format!("sealed checkpoint {checkpoint_id}; executing"),
            JsonValue::Null,
        )?;
        Ok(ApprovedExecutionToken::new(self.id, checkpoint_id))
    }

    pub fn record_snapshot_failure(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        error_message: &str,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Failed,
            EventStatus::Failed,
            error_message,
            JsonValue::Null,
        )
    }

    // --- EXECUTING -> {VERIFYING, ROLLING_BACK} ---

    pub fn record_execution_complete(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        metrics: JsonValue,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::Verifying,
            EventStatus::Started,
            "comparing actual to predicted diff",
            metrics,
        )
    }

    /// §28: "Execution failure (handler error, interrupt, unexpected
    /// exit) -> ROLLING_BACK, because persistent state may be partially
    /// modified."
    pub fn record_execution_failure(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        error_message: &str,
    ) -> Result<(), TransactionError> {
        self.advance(
            db,
            sink,
            TransactionState::RollingBack,
            EventStatus::Failed,
            error_message,
            JsonValue::Null,
        )
    }

    // --- VERIFYING -> {COMMITTED, ROLLING_BACK} ---

    pub fn record_verification_result(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        matched: bool,
        mismatch_detail: Option<&str>,
    ) -> Result<(), TransactionError> {
        if matched {
            self.advance(
                db,
                sink,
                TransactionState::Committed,
                EventStatus::Completed,
                "actual matched predicted; committed",
                JsonValue::Null,
            )
        } else {
            let detail = mismatch_detail.unwrap_or("actual diverged from predicted");
            self.write_audit(
                db,
                "verification_mismatch",
                &serde_json::json!({"detail": detail}),
            )?;
            self.advance(
                db,
                sink,
                TransactionState::RollingBack,
                EventStatus::Failed,
                detail,
                JsonValue::Null,
            )
        }
    }

    // --- ROLLING_BACK -> {RESTORED, ROLLBACK_FAILED} ---

    pub fn record_rollback_result(
        &mut self,
        db: &Database,
        sink: &mut dyn EventSink,
        success: bool,
        detail: Option<&str>,
    ) -> Result<(), TransactionError> {
        if success {
            self.advance(
                db,
                sink,
                TransactionState::Restored,
                EventStatus::Completed,
                "rollback succeeded",
                JsonValue::Null,
            )
        } else {
            // §13.3 / §27.4: "never silent" — an audit row, a terminal
            // state, and now (Build order phase 7) real session
            // quarantine: no further `Transaction::begin` on this
            // `session_id` will succeed until an explicit recovery action
            // (`rollback::quarantine_recovery_restore_to_newest`/
            // `..._reset_to_base`) runs and something calls
            // `Database::update_session_status` back to a non-quarantined
            // value.
            let detail = detail.unwrap_or("rollback did not succeed");
            self.write_audit(
                db,
                "rollback_failed",
                &serde_json::json!({"detail": detail}),
            )?;
            db.update_session_status(&self.session_id, "quarantined")?;
            self.advance(
                db,
                sink,
                TransactionState::RollbackFailed,
                EventStatus::Failed,
                detail,
                JsonValue::Null,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::backend::AiOutcome;
    use crate::db::session_queries::NewSession;
    use crate::parser::parse_line;
    use crate::policy::{PolicyDecision, ReasonCode, SupportTier};
    use crate::transaction::events::CollectingEventSink;
    use std::collections::HashMap;

    fn ai_skipped_outcome(reason: &str) -> AiOutcome {
        AiOutcome::Skipped {
            reason: reason.to_string(),
        }
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
            "rm -rf /project",
            None,
            &Utc::now().to_rfc3339(),
        )
        .unwrap();
        db
    }

    fn allow_decision() -> PolicyDecision {
        PolicyDecision {
            support_tier: SupportTier::Supported,
            verdict: Verdict::Allow,
            category: Some(Category::Safe),
            risk_level: Some(RiskLevel::Low),
            reason_codes: vec![],
            reasons: vec![],
        }
    }

    fn require_approval_decision() -> PolicyDecision {
        PolicyDecision {
            support_tier: SupportTier::Supported,
            verdict: Verdict::RequireApproval,
            category: Some(Category::DangerousContainable),
            risk_level: Some(RiskLevel::High),
            reason_codes: vec![],
            reasons: vec!["recursive deletion".into()],
        }
    }

    fn deny_decision() -> PolicyDecision {
        PolicyDecision {
            support_tier: SupportTier::Denied,
            verdict: Verdict::Deny,
            category: Some(Category::UnsafeToContain),
            risk_level: None,
            reason_codes: vec![ReasonCode::DenyShellInvocation],
            reasons: vec!["shell invocation".into()],
        }
    }

    fn unsupported_decision() -> PolicyDecision {
        PolicyDecision {
            support_tier: SupportTier::Unsupported,
            verdict: Verdict::RejectUnsupported,
            category: None,
            risk_level: None,
            reason_codes: vec![],
            reasons: vec!["not implemented".into()],
        }
    }

    #[test]
    fn category_1_safe_path_reaches_committed_and_persists_final_state() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("ls /project", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;

        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "ls /project").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &allow_decision())
            .unwrap();
        txn.record_ai_analysis_and_enter_simulation(
            &db,
            &mut sink,
            &ai_skipped_outcome("NullBackend"),
        )
        .unwrap();
        txn.record_simulation_complete(&db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_diff_ready(&db, &mut sink, false).unwrap();
        let checkpoint_id = CheckpointId(Ulid::new());
        let token = txn
            .record_snapshot_sealed(
                &db,
                &mut sink,
                checkpoint_id,
                "/layers/checkpoints/example",
                1,
                Some(1024),
            )
            .unwrap();
        assert_eq!(token.transaction_id(), txn.id);
        assert_eq!(token.checkpoint_id(), checkpoint_id);
        txn.record_execution_complete(&db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_verification_result(&db, &mut sink, true, None)
            .unwrap();

        assert_eq!(txn.state(), TransactionState::Committed);
        assert_eq!(
            db.get_transaction_final_state(&txn.id.to_string()).unwrap(),
            Some("COMMITTED".to_string())
        );
    }

    #[test]
    fn category_2_dangerous_path_via_rejection_never_reaches_snapshotting() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("rm -rf /project", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;

        let mut txn =
            Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "rm -rf /project").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &require_approval_decision())
            .unwrap();
        txn.record_ai_analysis_and_enter_simulation(
            &db,
            &mut sink,
            &ai_skipped_outcome("AI skipped"),
        )
        .unwrap();
        txn.record_simulation_complete(&db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_diff_ready(&db, &mut sink, true).unwrap();
        assert_eq!(txn.state(), TransactionState::WaitingForApproval);

        txn.reject(&db, &mut sink).unwrap();
        assert_eq!(txn.state(), TransactionState::Rejected);
        assert!(
            !sink
                .events
                .iter()
                .any(|e| e.stage == TransactionState::Snapshotting),
            "a rejected transaction must never reach SNAPSHOTTING"
        );
    }

    #[test]
    fn category_3_deny_never_reaches_ai_analysis_or_simulation() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("bash", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;

        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "bash").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &deny_decision())
            .unwrap();

        assert_eq!(txn.state(), TransactionState::Denied);
        assert!(
            !sink.events.iter().any(|e| matches!(
                e.stage,
                TransactionState::AiAnalysis | TransactionState::Simulating
            )),
            "a denied transaction must never reach AI_ANALYSIS or SIMULATING"
        );
    }

    #[test]
    fn unsupported_command_is_distinct_from_denied_in_both_state_and_audit() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("awk x", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;

        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "awk x").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &unsupported_decision())
            .unwrap();

        // Distinct state value from a real Deny.
        assert_eq!(txn.state(), TransactionState::Failed);

        // Distinct audit event_type, per this module's doc comment.
        let event_types: Vec<String> = db
            .raw_connection()
            .prepare("SELECT event_type FROM audit_log WHERE transaction_id = ?1")
            .unwrap()
            .query_map([txn.id.to_string()], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(event_types.contains(&"policy_rejected_unsupported".to_string()));
        assert!(!event_types.contains(&"policy_denied".to_string()));
    }

    #[test]
    fn verification_mismatch_triggers_rollback_and_a_failed_rollback_is_never_silent() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("rm -rf /project", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;

        let mut txn =
            Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "rm -rf /project").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &require_approval_decision())
            .unwrap();
        txn.record_ai_analysis_and_enter_simulation(
            &db,
            &mut sink,
            &ai_skipped_outcome("AI skipped"),
        )
        .unwrap();
        txn.record_simulation_complete(&db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_diff_ready(&db, &mut sink, true).unwrap();
        txn.approve(&db, &mut sink).unwrap();
        let checkpoint_id = CheckpointId(Ulid::new());
        txn.record_snapshot_sealed(
            &db,
            &mut sink,
            checkpoint_id,
            "/layers/checkpoints/example",
            1,
            Some(1024),
        )
        .unwrap();
        txn.record_execution_complete(&db, &mut sink, JsonValue::Null)
            .unwrap();
        txn.record_verification_result(&db, &mut sink, false, Some("unexpected file left behind"))
            .unwrap();
        assert_eq!(txn.state(), TransactionState::RollingBack);

        txn.record_rollback_result(&db, &mut sink, false, Some("layer discard failed"))
            .unwrap();
        assert_eq!(txn.state(), TransactionState::RollbackFailed);

        let event_types: Vec<String> = db
            .raw_connection()
            .prepare("SELECT event_type FROM audit_log WHERE transaction_id = ?1")
            .unwrap()
            .query_map([txn.id.to_string()], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            event_types.contains(&"rollback_failed".to_string()),
            "rollback failure must always write an audit row"
        );

        // §27.4: quarantine — no further command on this session may
        // begin a new transaction until it's explicitly recovered.
        assert_eq!(
            db.get_session_status("sess_1").unwrap(),
            Some("quarantined".to_string())
        );
        let next_attempt = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "ls");
        assert!(
            matches!(
                next_attempt,
                Err(TransactionError::SessionQuarantined { .. })
            ),
            "a quarantined session must refuse every new transaction, even a harmless one"
        );
    }

    #[test]
    fn a_non_quarantined_session_is_unaffected_by_another_sessions_quarantine() {
        let db = seeded_db();
        db.insert_session(&crate::db::session_queries::NewSession {
            id: "sess_2".into(),
            created_at: Utc::now().to_rfc3339(),
            layer_root_path: None,
            sandbox_backend: None,
            simulation_backend: None,
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();
        db.insert_command("cmd_2", "sess_2", "ls", None, &Utc::now().to_rfc3339())
            .unwrap();
        db.update_session_status("sess_1", "quarantined").unwrap();

        let mut sink = CollectingEventSink::default();
        let result = Transaction::begin(&db, &mut sink, "sess_2", "cmd_2", "ls");
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "illegal transaction state transition attempted")]
    fn illegal_transition_panics_in_debug_builds() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "ls").unwrap();
        // RECEIVED -> EXECUTING is nowhere in the legal table.
        let _ = txn.advance(
            &db,
            &mut sink,
            TransactionState::Executing,
            EventStatus::Started,
            "illegal",
            JsonValue::Null,
        );
    }

    #[test]
    fn sequence_numbers_are_monotonic_and_start_at_one() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("ls", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;
        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "ls").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &allow_decision())
            .unwrap();

        let sequences: Vec<u64> = sink.events.iter().map(|e| e.sequence).collect();
        assert_eq!(sequences, (1..=sequences.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn every_emitted_event_is_also_persisted_to_the_database() {
        let db = seeded_db();
        let mut sink = CollectingEventSink::default();
        let cmd = parse_line("ls", &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0;
        let mut txn = Transaction::begin(&db, &mut sink, "sess_1", "cmd_1", "ls").unwrap();
        txn.record_parsed(&db, &mut sink, &cmd).unwrap();
        txn.record_policy_decision(&db, &mut sink, &allow_decision())
            .unwrap();

        let persisted = db.get_transaction_events(&txn.id.to_string()).unwrap();
        assert_eq!(persisted.len(), sink.events.len());
    }
}
