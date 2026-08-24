// `TransactionEvent` type, its JSON wire representation, and the
// `EventSink` abstraction events are emitted through.

use chrono::{DateTime, Utc};

use crate::policy::{Category, RiskLevel};
use crate::transaction::manager::TransactionId;
use crate::transaction::state::TransactionState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    Started,
    InProgress,
    Completed,
    Failed,
}

impl EventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            EventStatus::Started => "started",
            EventStatus::InProgress => "in_progress",
            EventStatus::Completed => "completed",
            EventStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransactionEvent {
    pub transaction_id: TransactionId,
    pub session_id: String,
    pub command: String,
    pub stage: TransactionState,
    pub status: EventStatus,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: Option<u64>,
    pub category: Option<Category>,
    pub policy_risk_level: Option<RiskLevel>,
    pub metrics: serde_json::Value,
    pub message: String,
    pub sequence: u64,
}

fn category_str(category: Option<Category>) -> Option<&'static str> {
    category.map(|c| match c {
        Category::Safe => "safe",
        Category::DangerousContainable => "dangerous_containable",
        Category::UnsafeToContain => "unsafe_to_contain",
    })
}

fn risk_level_str(risk: Option<RiskLevel>) -> Option<&'static str> {
    risk.map(|r| match r {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    })
}

impl TransactionEvent {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "transaction_id": self.transaction_id.to_string(),
            "session_id": self.session_id,
            "command": self.command,
            "stage": self.stage.to_string(),
            "status": self.status.as_str(),
            "timestamp": self.timestamp.to_rfc3339(),
            "duration_ms": self.duration_ms,
            "category": category_str(self.category),
            "policy_risk_level": risk_level_str(self.policy_risk_level),
            "metrics": self.metrics,
            "message": self.message,
            "sequence": self.sequence,
        })
    }
}

pub trait EventSink {
    fn emit(&mut self, event: &TransactionEvent);
}

pub struct NullEventSink;

impl EventSink for NullEventSink {
    fn emit(&mut self, _event: &TransactionEvent) {}
}

#[derive(Default)]
pub struct CollectingEventSink {
    pub events: Vec<TransactionEvent>,
}

impl EventSink for CollectingEventSink {
    fn emit(&mut self, event: &TransactionEvent) {
        self.events.push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_matches_section_29_2s_shape() {
        let event = TransactionEvent {
            transaction_id: TransactionId::new(),
            session_id: "sess_01".into(),
            command: "rm -rf /project/build".into(),
            stage: TransactionState::Simulating,
            status: EventStatus::InProgress,
            timestamp: DateTime::parse_from_rfc3339("2026-08-22T10:15:32.114Z")
                .unwrap()
                .with_timezone(&Utc),
            duration_ms: None,
            category: Some(Category::DangerousContainable),
            policy_risk_level: Some(RiskLevel::High),
            metrics: serde_json::json!({"files_scanned": 53}),
            message: "Running simulation pass in disposable layer".into(),
            sequence: 7,
        };

        let json = event.to_json();
        assert_eq!(json["stage"], "SIMULATING");
        assert_eq!(json["status"], "in_progress");
        assert_eq!(json["category"], "dangerous_containable");
        assert_eq!(json["policy_risk_level"], "high");
        assert_eq!(json["sequence"], 7);
        assert_eq!(json["metrics"]["files_scanned"], 53);
        assert!(json["duration_ms"].is_null());
    }

    #[test]
    fn collecting_sink_records_every_emitted_event_in_order() {
        let mut sink = CollectingEventSink::default();
        let base = TransactionEvent {
            transaction_id: TransactionId::new(),
            session_id: "sess_01".into(),
            command: "ls".into(),
            stage: TransactionState::Received,
            status: EventStatus::Started,
            timestamp: Utc::now(),
            duration_ms: None,
            category: None,
            policy_risk_level: None,
            metrics: serde_json::Value::Null,
            message: String::new(),
            sequence: 1,
        };
        sink.emit(&base);
        let mut second = base.clone();
        second.stage = TransactionState::Parsed;
        second.sequence = 2;
        sink.emit(&second);

        assert_eq!(sink.events.len(), 2);
        assert_eq!(sink.events[0].stage, TransactionState::Received);
        assert_eq!(sink.events[1].stage, TransactionState::Parsed);
    }
}
