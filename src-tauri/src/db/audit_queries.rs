// Hash-chained audit log queries: appends tamper-evident rows to
// `audit_log` and verifies the integrity of the chain.

use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::db::Database;

const GENESIS_HASH: &str = "";

fn compute_content_hash(payload_json: &str, previous_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload_json.as_bytes());
    hasher.update(previous_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Database {
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
