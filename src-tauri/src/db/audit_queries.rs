//! The hash-chained `audit_log` table (§35): "each row's `content_hash` is
//! `sha256(payload_json || previous_row.content_hash)`, forming a hash
//! chain... lets SafeShell or an external script **detect** retroactive
//! edits or deletions. It does **not** prevent a local host-root actor
//! from rewriting the entire chain" — tamper-evident, not tamper-proof,
//! exactly as scoped there.

use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::db::Database;

/// The chain's first row has no predecessor; its `content_hash` is
/// computed against this fixed genesis value rather than `None`/empty
/// special-casing at every call site.
const GENESIS_HASH: &str = "";

fn compute_content_hash(payload_json: &str, previous_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload_json.as_bytes());
    hasher.update(previous_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Database {
    /// Appends one audit row, chained to whatever the current last row's
    /// hash is, and returns the new row's `content_hash`. Per §28's
    /// "Database write failure" row ("the transaction record or audit
    /// event cannot be persisted... the transaction does not proceed past
    /// its current stage"), callers must treat an `Err` here as fatal to
    /// the transaction's progress, not a best-effort log write.
    pub fn insert_audit_row(
        &self,
        transaction_id: Option<&str>,
        session_id: Option<&str>,
        event_type: &str,
        payload_json: &str,
        timestamp: &str,
    ) -> rusqlite::Result<String> {
        let previous_hash = self
            .latest_audit_hash()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let content_hash = compute_content_hash(payload_json, &previous_hash);

        self.conn
            .execute(
                "INSERT INTO audit_log (transaction_id, session_id, event_type, payload_json, timestamp, content_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![transaction_id, session_id, event_type, payload_json, timestamp, content_hash],
            )
            .map(|_| content_hash)
    }

    fn latest_audit_hash(&self) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT content_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
    }

    /// Re-walks the entire chain from genesis, recomputing each row's
    /// expected `content_hash` from its stored `payload_json` and the
    /// *previous row's stored* hash, and compares it to what's actually
    /// stored. Returns `Ok(true)` iff every row matches — the real
    /// tamper-evidence check §35 describes, not just documentation of the
    /// intent to have one.
    pub fn verify_audit_chain_integrity(&self) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json, content_hash FROM audit_log ORDER BY id ASC")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;

        let mut expected_previous = GENESIS_HASH.to_string();
        for (payload_json, stored_hash) in rows {
            let expected = compute_content_hash(&payload_json, &expected_previous);
            if expected != stored_hash {
                return Ok(false);
            }
            expected_previous = stored_hash;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_row_chains_from_the_genesis_hash() {
        let db = Database::open_in_memory().unwrap();
        let hash = db
            .insert_audit_row(None, None, "session_created", r#"{"a":1}"#, "t0")
            .unwrap();
        assert_eq!(hash, compute_content_hash(r#"{"a":1}"#, GENESIS_HASH));
    }

    #[test]
    fn each_row_chains_to_the_previous_rows_hash() {
        let db = Database::open_in_memory().unwrap();
        let hash1 = db
            .insert_audit_row(None, None, "event_a", "payload_a", "t0")
            .unwrap();
        let hash2 = db
            .insert_audit_row(None, None, "event_b", "payload_b", "t1")
            .unwrap();
        assert_eq!(hash2, compute_content_hash("payload_b", &hash1));
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn verify_chain_integrity_passes_on_an_untampered_chain() {
        let db = Database::open_in_memory().unwrap();
        db.insert_audit_row(None, None, "a", "payload_a", "t0")
            .unwrap();
        db.insert_audit_row(None, None, "b", "payload_b", "t1")
            .unwrap();
        db.insert_audit_row(None, None, "c", "payload_c", "t2")
            .unwrap();
        assert!(db.verify_audit_chain_integrity().unwrap());
    }

    #[test]
    fn verify_chain_integrity_detects_a_tampered_payload() {
        let db = Database::open_in_memory().unwrap();
        db.insert_audit_row(None, None, "a", "payload_a", "t0")
            .unwrap();
        db.insert_audit_row(None, None, "b", "payload_b", "t1")
            .unwrap();

        // Simulate exactly the tampering §35 says this chain can *detect*
        // (though not prevent, from a host-root actor) — edit a row's
        // payload directly via SQL, bypassing insert_audit_row.
        db.raw_connection()
            .execute(
                "UPDATE audit_log SET payload_json = 'tampered' WHERE event_type = 'a'",
                [],
            )
            .unwrap();

        assert!(!db.verify_audit_chain_integrity().unwrap());
    }

    #[test]
    fn verify_chain_integrity_is_trivially_true_for_an_empty_log() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.verify_audit_chain_integrity().unwrap());
    }
}
