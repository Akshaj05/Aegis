// Typed database queries for reading and writing AI plan records
// (`ai_plans` table) associated with transactions.

use rusqlite::params;

use crate::db::Database;

pub struct NewAiPlan<'a> {
    pub id: &'a str,
    pub transaction_id: &'a str,
    pub raw_response: Option<&'a str>,
    pub validated: bool,
    pub schema_version: Option<&'a str>,
    pub intent: Option<&'a str>,
    pub risk_level: Option<&'a str>,
    pub confidence: Option<f64>,
    pub recovery_recommendation_json: Option<&'a str>,
    pub explanation: Option<&'a str>,
    pub divergence_json: Option<&'a str>,
}

impl Database {
    pub fn insert_ai_plan(&self, plan: &NewAiPlan) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT INTO ai_plans (id, transaction_id, raw_response, validated, schema_version, intent, risk_level, confidence, recovery_recommendation_json, explanation, divergence_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    plan.id,
                    plan.transaction_id,
                    plan.raw_response,
                    plan.validated,
                    plan.schema_version,
                    plan.intent,
                    plan.risk_level,
                    plan.confidence,
                    plan.recovery_recommendation_json,
                    plan.explanation,
                    plan.divergence_json,
                ],
            )
            .map(|_| ())
    }

    pub fn get_ai_plan_validated(&self, transaction_id: &str) -> rusqlite::Result<Option<bool>> {
        self.conn
            .query_row(
                "SELECT validated FROM ai_plans WHERE transaction_id = ?1",
                params![transaction_id],
                |row| row.get::<_, bool>(0),
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

    pub fn get_ai_plan(&self, transaction_id: &str) -> rusqlite::Result<Option<AiPlanRow>> {
        self.conn
            .query_row(
                "SELECT schema_version, intent, risk_level, confidence, recovery_recommendation_json, explanation, divergence_json
                 FROM ai_plans WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok(AiPlanRow {
                        schema_version: row.get(0)?,
                        intent: row.get(1)?,
                        risk_level: row.get(2)?,
                        confidence: row.get(3)?,
                        recovery_recommendation_json: row.get(4)?,
                        explanation: row.get(5)?,
                        divergence_json: row.get(6)?,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct AiPlanRow {
    pub schema_version: Option<String>,
    pub intent: Option<String>,
    pub risk_level: Option<String>,
    pub confidence: Option<f64>,
    pub recovery_recommendation_json: Option<String>,
    pub explanation: Option<String>,
    pub divergence_json: Option<String>,
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
        db.insert_command("cmd_1", "sess_1", "mkdir project", None, "t0")
            .unwrap();
        db.insert_transaction("txn_1", "cmd_1", "sess_1", "t0")
            .unwrap();
        db
    }

    #[test]
    fn inserts_a_validated_ai_plan() {
        let db = seeded_db();
        db.insert_ai_plan(&NewAiPlan {
            id: "aiplan_1",
            transaction_id: "txn_1",
            raw_response: Some(r#"{"schema_version":"1.0"}"#),
            validated: true,
            schema_version: Some("1.0"),
            intent: Some("directory_create"),
            risk_level: Some("low"),
            confidence: Some(0.95),
            recovery_recommendation_json: Some(r#"{"strategy":"no_recovery_needed"}"#),
            explanation: Some("Creates a directory."),
            divergence_json: None,
        })
        .unwrap();

        assert_eq!(db.get_ai_plan_validated("txn_1").unwrap(), Some(true));
    }

    #[test]
    fn a_failed_validation_can_still_be_recorded_with_only_the_raw_response() {
        let db = seeded_db();
        db.insert_ai_plan(&NewAiPlan {
            id: "aiplan_1",
            transaction_id: "txn_1",
            raw_response: Some("not valid json"),
            validated: false,
            schema_version: None,
            intent: None,
            risk_level: None,
            confidence: None,
            recovery_recommendation_json: None,
            explanation: None,
            divergence_json: None,
        })
        .unwrap();

        assert_eq!(db.get_ai_plan_validated("txn_1").unwrap(), Some(false));
    }

    #[test]
    fn unknown_transaction_id_is_none_not_an_error() {
        let db = seeded_db();
        assert_eq!(db.get_ai_plan_validated("nonexistent").unwrap(), None);
    }

    #[test]
    fn get_ai_plan_returns_the_full_row() {
        let db = seeded_db();
        db.insert_ai_plan(&NewAiPlan {
            id: "aiplan_1",
            transaction_id: "txn_1",
            raw_response: None,
            validated: true,
            schema_version: Some("1.0"),
            intent: Some("directory_create"),
            risk_level: Some("low"),
            confidence: Some(0.95),
            recovery_recommendation_json: Some(r#"{"strategy":"no_recovery_needed"}"#),
            explanation: Some("Creates a directory."),
            divergence_json: None,
        })
        .unwrap();

        let plan = db.get_ai_plan("txn_1").unwrap().unwrap();
        assert_eq!(plan.intent.as_deref(), Some("directory_create"));
        assert_eq!(plan.confidence, Some(0.95));
    }

    #[test]
    fn get_ai_plan_is_none_when_nothing_was_recorded() {
        let db = seeded_db();
        assert_eq!(db.get_ai_plan("txn_1").unwrap(), None);
    }
}
