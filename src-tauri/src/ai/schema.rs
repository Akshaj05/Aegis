// Defines the structured AI plan schema (closed enums, plan fields) and
// the outgoing AiRequest shape sent to an AI backend.

use serde::{Deserialize, Serialize};

use crate::policy::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Navigation,
    FileRead,
    FileWrite,
    DirectoryCreate,
    RecursiveDelete,
    PermissionChange,
    OwnershipChange,
    PackageRemoval,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    RestorePreTransactionSnapshot,
    NoRecoveryNeeded,
    NotReversible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRecommendation {
    pub strategy: RecoveryStrategy,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictedEffects {
    pub files_deleted_estimate: u32,
    pub directories_deleted_estimate: u32,
    pub escapes_sandbox: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiPlan {
    pub schema_version: String,
    pub command: String,
    pub intent: Intent,
    pub risk_level: RiskLevel,
    pub affected_resources: Vec<String>,
    pub predicted_effects: PredictedEffects,
    pub preconditions: Vec<String>,
    pub reversible_within_safeshell: bool,
    pub recovery_recommendation: RecoveryRecommendation,
    pub external_side_effects: bool,
    pub confidence: f64,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiRequest {
    pub command_text: String,
    pub category: Option<&'static str>,
    pub risk_level: Option<RiskLevel>,
    pub policy_reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "schema_version": "1.0",
            "command": "rm -rf /project/build",
            "intent": "recursive_delete",
            "risk_level": "high",
            "affected_resources": ["/project/build"],
            "predicted_effects": {
                "files_deleted_estimate": 47,
                "directories_deleted_estimate": 6,
                "escapes_sandbox": false
            },
            "preconditions": ["path exists within the simulated root"],
            "reversible_within_safeshell": true,
            "recovery_recommendation": {
                "strategy": "restore_pre_transaction_snapshot",
                "description": "Use Undo Last Transaction."
            },
            "external_side_effects": false,
            "confidence": 0.82,
            "explanation": "This recursively deletes the build directory."
        }"#
    }

    #[test]
    fn the_architecture_examples_json_deserializes() {
        let plan: AiPlan = serde_json::from_str(sample_json()).unwrap();
        assert_eq!(plan.intent, Intent::RecursiveDelete);
        assert_eq!(plan.risk_level, RiskLevel::High);
        assert_eq!(
            plan.recovery_recommendation.strategy,
            RecoveryStrategy::RestorePreTransactionSnapshot
        );
    }

    #[test]
    fn an_unrecognized_intent_fails_to_deserialize_rather_than_defaulting() {
        let json = sample_json().replace("recursive_delete", "delete_the_universe");
        let result: Result<AiPlan, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn an_unrecognized_risk_level_fails_to_deserialize() {
        let json = sample_json().replace("\"risk_level\": \"high\"", "\"risk_level\": \"extreme\"");
        let result: Result<AiPlan, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn round_tripping_through_serialize_then_deserialize_is_lossless() {
        let plan: AiPlan = serde_json::from_str(sample_json()).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        let round_tripped: AiPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, round_tripped);
    }
}
