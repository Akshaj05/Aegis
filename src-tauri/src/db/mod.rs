// SQLite schema definition and connection management for the application
// database, plus module wiring for the typed query submodules.

use std::path::Path;

use rusqlite::Connection;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Database { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(SCHEMA_SQL)
    }

    #[cfg(test)]
    pub(crate) fn raw_connection(&self) -> &Connection {
        &self.conn
    }
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  layer_root_path TEXT,
  sandbox_backend TEXT,
  simulation_backend TEXT,
  capability_report_json TEXT,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  raw_input TEXT NOT NULL,
  parsed_ast TEXT,
  submitted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL REFERENCES commands(id),
  session_id TEXT NOT NULL REFERENCES sessions(id),
  final_state TEXT,
  category TEXT,
  support_tier TEXT,
  policy_risk_level TEXT,
  policy_reason_codes TEXT,
  ai_risk_level TEXT,
  ai_skipped INTEGER,
  ai_skipped_reason TEXT,
  requires_approval INTEGER,
  approved_by_user INTEGER,
  approved_at TEXT,
  pre_execution_checkpoint_id TEXT REFERENCES snapshots(id),
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS transaction_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id TEXT NOT NULL REFERENCES transactions(id),
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  duration_ms INTEGER,
  metrics_json TEXT,
  message TEXT,
  sequence INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_plans (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES transactions(id),
  raw_response TEXT,
  validated INTEGER,
  schema_version TEXT,
  intent TEXT,
  risk_level TEXT,
  confidence REAL,
  recovery_recommendation_json TEXT,
  explanation TEXT,
  divergence_json TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  transaction_id TEXT REFERENCES transactions(id),
  layer_path TEXT NOT NULL,
  layer_ordinal INTEGER NOT NULL,
  size_bytes INTEGER,
  sealed_at TEXT NOT NULL,
  recoverable INTEGER NOT NULL,
  gc_reason TEXT
);

CREATE TABLE IF NOT EXISTS execution_results (
  transaction_id TEXT PRIMARY KEY REFERENCES transactions(id),
  exit_code INTEGER,
  stdout TEXT,
  stderr TEXT,
  files_created INTEGER,
  files_modified INTEGER,
  files_deleted INTEGER,
  bytes_affected INTEGER,
  executed_at TEXT
);

CREATE TABLE IF NOT EXISTS verification_results (
  transaction_id TEXT PRIMARY KEY REFERENCES transactions(id),
  predicted_diff_json TEXT,
  actual_diff_json TEXT,
  matched INTEGER,
  mismatch_kind TEXT,
  mismatch_details TEXT
);

CREATE TABLE IF NOT EXISTS rollback_events (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL REFERENCES transactions(id),
  reason TEXT NOT NULL,
  restored_checkpoint_id TEXT REFERENCES snapshots(id),
  success INTEGER NOT NULL,
  failure_detail TEXT,
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id TEXT,
  session_id TEXT,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  content_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS terminal_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  command_text TEXT NOT NULL,
  entered_at TEXT NOT NULL
);
"#;

pub mod ai_queries;
pub mod audit_queries;
pub mod session_queries;
pub mod snapshot_queries;
pub mod transaction_queries;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_in_memory_and_creates_every_table() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.raw_connection();
        let expected_tables = [
            "sessions",
            "commands",
            "transactions",
            "transaction_events",
            "ai_plans",
            "snapshots",
            "execution_results",
            "verification_results",
            "rollback_events",
            "audit_log",
            "terminal_history",
        ];
        for table in expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {table} was not created");
        }
    }

    #[test]
    fn opening_twice_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("safeshell.db");
        Database::open(&path).unwrap();
        Database::open(&path).unwrap();
    }
}
