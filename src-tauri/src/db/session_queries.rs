//! Typed queries against `sessions` and `commands` (§34).

use rusqlite::params;

use crate::db::Database;

#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: String,
    pub created_at: String,
    pub layer_root_path: Option<String>,
    pub sandbox_backend: Option<String>,
    pub simulation_backend: Option<String>,
    pub capability_report_json: Option<String>,
    pub status: String,
}

impl Database {
    pub fn insert_session(&self, session: &NewSession) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (id, created_at, layer_root_path, sandbox_backend, simulation_backend, capability_report_json, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                session.id,
                session.created_at,
                session.layer_root_path,
                session.sandbox_backend,
                session.simulation_backend,
                session.capability_report_json,
                session.status,
            ],
        )
        .map(|_rows_affected| ())
    }

    pub fn insert_command(
        &self,
        id: &str,
        session_id: &str,
        raw_input: &str,
        parsed_ast_json: Option<&str>,
        submitted_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO commands (id, session_id, raw_input, parsed_ast, submitted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, session_id, raw_input, parsed_ast_json, submitted_at],
            )
            .map(|_rows_affected| ())
    }

    pub fn update_session_status(&self, id: &str, status: &str) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "UPDATE sessions SET status = ?2 WHERE id = ?1",
                params![id, status],
            )
            .map(|_| ())
    }

    pub fn get_session_status(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT status FROM sessions WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
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

    /// `list_sessions`'s (§30) source, newest first.
    pub fn list_sessions(&self) -> rusqlite::Result<Vec<SessionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at, simulation_backend, status FROM sessions ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SessionRow {
                id: row.get(0)?,
                created_at: row.get(1)?,
                simulation_backend: row.get(2)?,
                status: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// §17.8's per-session scrollback (`terminal_history`, §34) — distinct
    /// from `TerminalSession::record_history` (in-memory, per process
    /// lifetime only); this is the persisted copy `get_transaction_history`
    /// adjacent UI (§31.2's bottom strip) can read back across restarts.
    pub fn insert_terminal_history(
        &self,
        session_id: &str,
        command_text: &str,
        entered_at: &str,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO terminal_history (session_id, command_text, entered_at) VALUES (?1, ?2, ?3)",
                params![session_id, command_text, entered_at],
            )
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionRow {
    pub id: String,
    pub created_at: String,
    pub simulation_backend: Option<String>,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn inserts_a_session_and_a_command_referencing_it() {
        let db = Database::open_in_memory().unwrap();
        db.insert_session(&NewSession {
            id: "sess_1".into(),
            created_at: "2026-08-22T00:00:00Z".into(),
            layer_root_path: None,
            sandbox_backend: Some("namespace".into()),
            simulation_backend: Some("copyup".into()),
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();

        db.insert_command(
            "cmd_1",
            "sess_1",
            "rm -rf /project",
            None,
            "2026-08-22T00:00:01Z",
        )
        .unwrap();
    }

    #[test]
    fn session_status_can_be_read_back_and_updated() {
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

        assert_eq!(
            db.get_session_status("sess_1").unwrap(),
            Some("active".to_string())
        );

        db.update_session_status("sess_1", "quarantined").unwrap();
        assert_eq!(
            db.get_session_status("sess_1").unwrap(),
            Some("quarantined".to_string())
        );
    }

    #[test]
    fn unknown_session_status_is_none_not_an_error() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.get_session_status("nonexistent").unwrap(), None);
    }

    #[test]
    fn list_sessions_returns_newest_first() {
        let db = Database::open_in_memory().unwrap();
        db.insert_session(&NewSession {
            id: "sess_1".into(),
            created_at: "t0".into(),
            layer_root_path: None,
            sandbox_backend: None,
            simulation_backend: Some("copyup".into()),
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();
        db.insert_session(&NewSession {
            id: "sess_2".into(),
            created_at: "t1".into(),
            layer_root_path: None,
            sandbox_backend: None,
            simulation_backend: Some("copyup".into()),
            capability_report_json: None,
            status: "active".into(),
        })
        .unwrap();

        let sessions = db.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "sess_2");
        assert_eq!(sessions[1].id, "sess_1");
    }

    #[test]
    fn terminal_history_inserts_without_error() {
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
        db.insert_terminal_history("sess_1", "ls -la", "t1")
            .unwrap();
    }
}
