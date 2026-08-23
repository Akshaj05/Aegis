//! Typed queries against `snapshots` (§34). This is what Build order
//! phase 5's `transaction::manager::Transaction::record_snapshot_sealed`
//! deliberately left unwired — see that method's doc comment for why
//! (setting `transactions.pre_execution_checkpoint_id` before any
//! `snapshots` row existed was a real `FOREIGN KEY constraint failed` bug,
//! not a hypothetical one). This module is what closes that gap: insert
//! the `snapshots` row *first*, then the FK reference is satisfiable.

use rusqlite::params;

use crate::db::Database;

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub fn insert_snapshot(
        &self,
        id: &str,
        session_id: &str,
        transaction_id: Option<&str>,
        layer_path: &str,
        layer_ordinal: i64,
        size_bytes: Option<i64>,
        sealed_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO snapshots (id, session_id, transaction_id, layer_path, layer_ordinal, size_bytes, sealed_at, recoverable, gc_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL)",
                params![id, session_id, transaction_id, layer_path, layer_ordinal, size_bytes, sealed_at],
            )
            .map(|_| ())
    }

    /// §23.4: "update `snapshots.recoverable = 0` for the affected
    /// checkpoint... in the same database transaction that records the
    /// squash." Callers wrap this and `insert_audit_row`'s `snapshot_gc`
    /// event in one SQLite transaction (`rusqlite::Connection::transaction`)
    /// — this method itself is just the one `UPDATE`.
    pub fn mark_snapshot_unrecoverable(&self, id: &str, gc_reason: &str) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE snapshots SET recoverable = 0, gc_reason = ?2 WHERE id = ?1",
                params![id, gc_reason],
            )
            .map(|_| ())
    }

    pub fn get_snapshot_recoverable(&self, id: &str) -> rusqlite::Result<Option<bool>> {
        self.conn
            .query_row(
                "SELECT recoverable FROM snapshots WHERE id = ?1",
                params![id],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .map(Some)
            .or_else(|e| {
                if e == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    /// Build order phase 10: `get_storage_status`'s (§41)
    /// `oldest_recoverable_transaction_id` field names a transaction, not
    /// a checkpoint — the orchestrator has the oldest checkpoint id
    /// readily in-memory (`LayerStack.checkpoints`) but needs this join to
    /// report which transaction sealed it.
    pub fn get_snapshot_transaction_id(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT transaction_id FROM snapshots WHERE id = ?1",
                params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .or_else(|e| {
                if e == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_queries::NewSession;

    fn seeded_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        db.insert_session(&NewSession {
            id: "sess_1".into(),
            created_at: "t0".into(),
            layer_root_path: None,
            sandbox_backend: None,
            simulation_backend: None,
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();
        db
    }

    #[test]
    fn inserts_a_snapshot_recoverable_by_default() {
        let db = seeded_db();
        db.insert_snapshot(
            "ckpt_1",
            "sess_1",
            None,
            "/layers/checkpoints/ckpt_1",
            1,
            Some(1024),
            "t1",
        )
        .unwrap();
        assert_eq!(db.get_snapshot_recoverable("ckpt_1").unwrap(), Some(true));
    }

    #[test]
    fn marking_unrecoverable_updates_the_flag_and_reason() {
        let db = seeded_db();
        db.insert_snapshot(
            "ckpt_1",
            "sess_1",
            None,
            "/layers/checkpoints/ckpt_1",
            1,
            None,
            "t1",
        )
        .unwrap();
        db.mark_snapshot_unrecoverable("ckpt_1", "retention_count")
            .unwrap();
        assert_eq!(db.get_snapshot_recoverable("ckpt_1").unwrap(), Some(false));
    }

    #[test]
    fn a_transaction_can_reference_an_existing_snapshot_via_foreign_key() {
        let db = seeded_db();
        db.insert_command("cmd_1", "sess_1", "rm -rf /project", None, "t0")
            .unwrap();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "t0")
            .unwrap();
        db.insert_snapshot(
            "ckpt_1",
            "sess_1",
            Some("txn_1"),
            "/layers/checkpoints/ckpt_1",
            1,
            None,
            "t1",
        )
        .unwrap();

        // This is exactly what failed before this module existed —
        // proof the ordering fix actually works end to end.
        db.update_transaction_checkpoint("txn_1", "ckpt_1").unwrap();
    }

    #[test]
    fn unknown_snapshot_id_is_none_not_an_error() {
        let db = seeded_db();
        assert_eq!(db.get_snapshot_recoverable("nonexistent").unwrap(), None);
    }

    #[test]
    fn get_snapshot_transaction_id_returns_the_sealing_transaction() {
        let db = seeded_db();
        db.insert_command("cmd_1", "sess_1", "rm -rf /project", None, "t0")
            .unwrap();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "t0")
            .unwrap();
        db.insert_snapshot(
            "ckpt_1",
            "sess_1",
            Some("txn_1"),
            "/layers/checkpoints/ckpt_1",
            1,
            None,
            "t1",
        )
        .unwrap();

        assert_eq!(
            db.get_snapshot_transaction_id("ckpt_1").unwrap(),
            Some("txn_1".to_string())
        );
        assert_eq!(db.get_snapshot_transaction_id("nonexistent").unwrap(), None);
    }
}
