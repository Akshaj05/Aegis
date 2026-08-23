//! Typed queries against `transactions` and `transaction_events` (§34).
//!
//! Deliberately takes primitive/string parameters rather than importing
//! types from `transaction/` — `db/` is the lower layer here (`transaction/`
//! depends on `db/`, not the reverse), matching how `sandbox/worker/`
//! depends on `sandbox/syscalls.rs` and not vice versa elsewhere in this
//! crate. Callers in `transaction/` convert their own enums to the
//! `&str`/`Option<&str>` this expects.

use rusqlite::params;

use crate::db::Database;

impl Database {
    pub fn insert_transaction(
        &self,
        id: &str,
        command_id: &str,
        session_id: &str,
        created_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute("INSERT INTO transactions (id, command_id, session_id, created_at) VALUES (?1, ?2, ?3, ?4)", params![id, command_id, session_id, created_at])
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_transaction_policy_fields(
        &self,
        id: &str,
        category: Option<&str>,
        support_tier: &str,
        policy_risk_level: Option<&str>,
        policy_reason_codes_json: &str,
        requires_approval: bool,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE transactions SET category = ?2, support_tier = ?3, policy_risk_level = ?4, policy_reason_codes = ?5, requires_approval = ?6 WHERE id = ?1",
                params![id, category, support_tier, policy_risk_level, policy_reason_codes_json, requires_approval as i64],
            )
            .map(|_| ())
    }

    pub fn update_transaction_ai_fields(
        &self,
        id: &str,
        ai_risk_level: Option<&str>,
        ai_skipped: bool,
        ai_skipped_reason: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE transactions SET ai_risk_level = ?2, ai_skipped = ?3, ai_skipped_reason = ?4 WHERE id = ?1",
                params![id, ai_risk_level, ai_skipped as i64, ai_skipped_reason],
            )
            .map(|_| ())
    }

    pub fn update_transaction_approval(
        &self,
        id: &str,
        approved_by_user: bool,
        approved_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE transactions SET approved_by_user = ?2, approved_at = ?3 WHERE id = ?1",
                params![id, approved_by_user as i64, approved_at],
            )
            .map(|_| ())
    }

    /// Sets a foreign key into `snapshots(id)` — callers **must** insert
    /// the corresponding `snapshots` row first, or this fails with a
    /// `FOREIGN KEY constraint failed` error (found the hard way: an
    /// earlier version of `transaction::manager::Transaction::record_snapshot_sealed`
    /// called this before any `snapshots` row existed at all, since
    /// nothing creates one yet — that's the Snapshot Manager, Build order
    /// phase 7). Not called anywhere in this codebase yet for exactly
    /// that reason; kept ready for phase 7 to call once it inserts the
    /// snapshot row this points at.
    pub fn update_transaction_checkpoint(
        &self,
        id: &str,
        checkpoint_id: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE transactions SET pre_execution_checkpoint_id = ?2 WHERE id = ?1",
                params![id, checkpoint_id],
            )
            .map(|_| ())
    }

    pub fn update_transaction_final_state(
        &self,
        id: &str,
        final_state: &str,
        completed_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE transactions SET final_state = ?2, completed_at = ?3 WHERE id = ?1",
                params![id, final_state, completed_at],
            )
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_transaction_event(
        &self,
        transaction_id: &str,
        stage: &str,
        status: &str,
        timestamp: &str,
        duration_ms: Option<i64>,
        metrics_json: Option<&str>,
        message: &str,
        sequence: i64,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO transaction_events (transaction_id, stage, status, timestamp, duration_ms, metrics_json, message, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![transaction_id, stage, status, timestamp, duration_ms, metrics_json, message, sequence],
            )
            .map(|_| ())
    }

    /// Ordered by `sequence`, matching §29.2's "monotonic per-transaction
    /// counter so the frontend can detect dropped or out-of-order events."
    pub fn get_transaction_events(
        &self,
        transaction_id: &str,
    ) -> rusqlite::Result<Vec<TransactionEventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT transaction_id, stage, status, timestamp, duration_ms, metrics_json, message, sequence
             FROM transaction_events WHERE transaction_id = ?1 ORDER BY sequence ASC",
        )?;
        let rows = stmt.query_map(params![transaction_id], |row| {
            Ok(TransactionEventRow {
                transaction_id: row.get(0)?,
                stage: row.get(1)?,
                status: row.get(2)?,
                timestamp: row.get(3)?,
                duration_ms: row.get(4)?,
                metrics_json: row.get(5)?,
                message: row.get(6)?,
                sequence: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_transaction_final_state(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.conn.query_row(
            "SELECT final_state FROM transactions WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
    }

    /// Build order phase 10: `get_transaction_detail`'s (§41) Rust-side
    /// source. Joins `commands.raw_input` since the IPC contract's detail
    /// shape includes the original command text and `transactions` itself
    /// only stores a `command_id` foreign key, not the text.
    pub fn get_transaction_row(&self, id: &str) -> rusqlite::Result<Option<TransactionRow>> {
        self.conn
            .query_row(
                "SELECT t.id, t.command_id, t.session_id, c.raw_input, t.final_state, t.category,
                        t.support_tier, t.policy_risk_level, t.policy_reason_codes, t.ai_risk_level,
                        t.ai_skipped, t.ai_skipped_reason, t.requires_approval, t.approved_by_user,
                        t.approved_at, t.pre_execution_checkpoint_id, t.created_at, t.completed_at
                 FROM transactions t JOIN commands c ON c.id = t.command_id
                 WHERE t.id = ?1",
                params![id],
                |row| {
                    Ok(TransactionRow {
                        id: row.get(0)?,
                        command_id: row.get(1)?,
                        session_id: row.get(2)?,
                        raw_command: row.get(3)?,
                        final_state: row.get(4)?,
                        category: row.get(5)?,
                        support_tier: row.get(6)?,
                        policy_risk_level: row.get(7)?,
                        policy_reason_codes: row.get(8)?,
                        ai_risk_level: row.get(9)?,
                        ai_skipped: row.get::<_, Option<i64>>(10)?.map(|v| v != 0),
                        ai_skipped_reason: row.get(11)?,
                        requires_approval: row.get::<_, Option<i64>>(12)?.map(|v| v != 0),
                        approved_by_user: row.get::<_, Option<i64>>(13)?.map(|v| v != 0),
                        approved_at: row.get(14)?,
                        pre_execution_checkpoint_id: row.get(15)?,
                        created_at: row.get(16)?,
                        completed_at: row.get(17)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| {
                if e == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    /// `get_transaction_history`'s (§41) source, newest first. `limit`/
    /// `offset` implement §30's `page` parameter as a simple offset page —
    /// the smallest thing that actually paginates, matching this table's
    /// expected row count (transaction history, not an unbounded log).
    pub fn get_transactions_for_session(
        &self,
        session_id: &str,
        limit: i64,
        offset: i64,
    ) -> rusqlite::Result<Vec<TransactionSummaryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.id, c.raw_input, t.final_state, t.category, t.policy_risk_level,
                    t.requires_approval, t.created_at, t.completed_at
             FROM transactions t JOIN commands c ON c.id = t.command_id
             WHERE t.session_id = ?1
             ORDER BY t.created_at DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![session_id, limit, offset], |row| {
            Ok(TransactionSummaryRow {
                id: row.get(0)?,
                raw_command: row.get(1)?,
                final_state: row.get(2)?,
                category: row.get(3)?,
                policy_risk_level: row.get(4)?,
                requires_approval: row.get::<_, Option<i64>>(5)?.map(|v| v != 0),
                created_at: row.get(6)?,
                completed_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_execution_result(
        &self,
        transaction_id: &str,
        exit_code: i32,
        stdout: &str,
        stderr: &str,
        files_created: i64,
        files_modified: i64,
        files_deleted: i64,
        bytes_affected: i64,
        executed_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO execution_results (transaction_id, exit_code, stdout, stderr, files_created, files_modified, files_deleted, bytes_affected, executed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![transaction_id, exit_code, stdout, stderr, files_created, files_modified, files_deleted, bytes_affected, executed_at],
            )
            .map(|_| ())
    }

    pub fn get_execution_result(
        &self,
        transaction_id: &str,
    ) -> rusqlite::Result<Option<ExecutionResultRow>> {
        self.conn
            .query_row(
                "SELECT exit_code, stdout, stderr, files_created, files_modified, files_deleted, bytes_affected, executed_at
                 FROM execution_results WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok(ExecutionResultRow {
                        exit_code: row.get(0)?,
                        stdout: row.get(1)?,
                        stderr: row.get(2)?,
                        files_created: row.get(3)?,
                        files_modified: row.get(4)?,
                        files_deleted: row.get(5)?,
                        bytes_affected: row.get(6)?,
                        executed_at: row.get(7)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| {
                if e == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_verification_result(
        &self,
        transaction_id: &str,
        predicted_diff_json: &str,
        actual_diff_json: &str,
        matched: bool,
        mismatch_kind: Option<&str>,
        mismatch_details: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO verification_results (transaction_id, predicted_diff_json, actual_diff_json, matched, mismatch_kind, mismatch_details)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![transaction_id, predicted_diff_json, actual_diff_json, matched as i64, mismatch_kind, mismatch_details],
            )
            .map(|_| ())
    }

    pub fn get_verification_result(
        &self,
        transaction_id: &str,
    ) -> rusqlite::Result<Option<VerificationResultRow>> {
        self.conn
            .query_row(
                "SELECT predicted_diff_json, actual_diff_json, matched, mismatch_kind, mismatch_details
                 FROM verification_results WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok(VerificationResultRow {
                        predicted_diff_json: row.get(0)?,
                        actual_diff_json: row.get(1)?,
                        matched: row.get::<_, i64>(2)? != 0,
                        mismatch_kind: row.get(3)?,
                        mismatch_details: row.get(4)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| {
                if e == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_rollback_event(
        &self,
        id: &str,
        transaction_id: &str,
        reason: &str,
        restored_checkpoint_id: Option<&str>,
        success: bool,
        failure_detail: Option<&str>,
        occurred_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO rollback_events (id, transaction_id, reason, restored_checkpoint_id, success, failure_detail, occurred_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, transaction_id, reason, restored_checkpoint_id, success as i64, failure_detail, occurred_at],
            )
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TransactionEventRow {
    pub transaction_id: String,
    pub stage: String,
    pub status: String,
    pub timestamp: String,
    pub duration_ms: Option<i64>,
    pub metrics_json: Option<String>,
    pub message: String,
    pub sequence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRow {
    pub id: String,
    pub command_id: String,
    pub session_id: String,
    pub raw_command: String,
    pub final_state: Option<String>,
    pub category: Option<String>,
    pub support_tier: Option<String>,
    pub policy_risk_level: Option<String>,
    pub policy_reason_codes: Option<String>,
    pub ai_risk_level: Option<String>,
    pub ai_skipped: Option<bool>,
    pub ai_skipped_reason: Option<String>,
    pub requires_approval: Option<bool>,
    pub approved_by_user: Option<bool>,
    pub approved_at: Option<String>,
    pub pre_execution_checkpoint_id: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TransactionSummaryRow {
    pub id: String,
    pub raw_command: String,
    pub final_state: Option<String>,
    pub category: Option<String>,
    pub policy_risk_level: Option<String>,
    pub requires_approval: Option<bool>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExecutionResultRow {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub files_created: i64,
    pub files_modified: i64,
    pub files_deleted: i64,
    pub bytes_affected: i64,
    pub executed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResultRow {
    pub predicted_diff_json: String,
    pub actual_diff_json: String,
    pub matched: bool,
    pub mismatch_kind: Option<String>,
    pub mismatch_details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_queries::NewSession;

    fn seeded_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        db.insert_session(&NewSession {
            id: "sess_1".into(),
            created_at: "2026-08-22T00:00:00Z".into(),
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
            "2026-08-22T00:00:00Z",
        )
        .unwrap();
        db
    }

    #[test]
    fn inserts_and_updates_a_transaction() {
        let db = seeded_db();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "2026-08-22T00:00:00Z")
            .unwrap();
        db.update_transaction_policy_fields(
            "txn_1",
            Some("dangerous_containable"),
            "supported",
            Some("high"),
            "[]",
            true,
        )
        .unwrap();
        db.update_transaction_final_state("txn_1", "COMMITTED", "2026-08-22T00:00:05Z")
            .unwrap();

        let state = db.get_transaction_final_state("txn_1").unwrap();
        assert_eq!(state, Some("COMMITTED".to_string()));
    }

    #[test]
    fn transaction_events_come_back_ordered_by_sequence() {
        let db = seeded_db();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "2026-08-22T00:00:00Z")
            .unwrap();
        db.insert_transaction_event(
            "txn_1",
            "PARSED",
            "completed",
            "t1",
            Some(1),
            None,
            "parsed",
            1,
        )
        .unwrap();
        db.insert_transaction_event(
            "txn_1",
            "POLICY_CHECK",
            "completed",
            "t2",
            Some(1),
            None,
            "checked",
            2,
        )
        .unwrap();

        let events = db.get_transaction_events("txn_1").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].stage, "PARSED");
        assert_eq!(events[1].stage, "POLICY_CHECK");
    }

    #[test]
    fn get_transaction_row_joins_the_raw_command_text() {
        let db = seeded_db();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "2026-08-22T00:00:00Z")
            .unwrap();
        db.update_transaction_policy_fields(
            "txn_1",
            Some("dangerous_containable"),
            "supported",
            Some("high"),
            "[]",
            true,
        )
        .unwrap();

        let row = db.get_transaction_row("txn_1").unwrap().unwrap();
        assert_eq!(row.raw_command, "rm -rf /project");
        assert_eq!(row.category.as_deref(), Some("dangerous_containable"));
        assert_eq!(row.requires_approval, Some(true));
    }

    #[test]
    fn get_transaction_row_is_none_for_an_unknown_id() {
        let db = seeded_db();
        assert_eq!(db.get_transaction_row("nonexistent").unwrap(), None);
    }

    #[test]
    fn transactions_for_session_come_back_newest_first_and_respect_paging() {
        let db = seeded_db();
        for (i, ts) in ["t0", "t1", "t2"].iter().enumerate() {
            let txn_id = format!("txn_{i}");
            db.insert_transaction(&txn_id, "cmd_1", "sess_1", ts)
                .unwrap();
        }

        let page = db.get_transactions_for_session("sess_1", 2, 0).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, "txn_2");
        assert_eq!(page[1].id, "txn_1");

        let next_page = db.get_transactions_for_session("sess_1", 2, 2).unwrap();
        assert_eq!(next_page.len(), 1);
        assert_eq!(next_page[0].id, "txn_0");
    }

    #[test]
    fn execution_and_verification_results_round_trip() {
        let db = seeded_db();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "2026-08-22T00:00:00Z")
            .unwrap();
        db.insert_execution_result("txn_1", 0, "out", "", 1, 0, 0, 42, "2026-08-22T00:00:01Z")
            .unwrap();
        let exec = db.get_execution_result("txn_1").unwrap().unwrap();
        assert_eq!(exec.exit_code, 0);
        assert_eq!(exec.stdout, "out");
        assert_eq!(exec.bytes_affected, 42);

        db.insert_verification_result(
            "txn_1",
            "{}",
            "{}",
            false,
            Some("content_hash_differs"),
            Some("detail"),
        )
        .unwrap();
        let verification = db.get_verification_result("txn_1").unwrap().unwrap();
        assert!(!verification.matched);
        assert_eq!(
            verification.mismatch_kind.as_deref(),
            Some("content_hash_differs")
        );
    }

    #[test]
    fn rollback_event_inserts_without_error() {
        let db = seeded_db();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "2026-08-22T00:00:00Z")
            .unwrap();
        db.insert_rollback_event(
            "rb_1",
            "txn_1",
            "verification_mismatch",
            None,
            true,
            None,
            "2026-08-22T00:00:02Z",
        )
        .unwrap();
    }
}
