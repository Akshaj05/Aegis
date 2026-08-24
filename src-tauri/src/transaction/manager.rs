// `Transaction` — drives one command through the transaction state machine,
// persisting each transition and emitting its event; the only way a
// `Transaction`'s state changes anywhere in this crate.

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

        assert_eq!(txn.state(), TransactionState::Failed);

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
