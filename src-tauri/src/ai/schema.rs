//! §21.6's structured output schema, plus the outgoing request shape the
//! Rust core sends. Every enum here is closed (§21.7: "Enum-constrained
//! fields... against closed taxonomies. Values outside the enum are
//! rejected, never coerced") — `serde`'s derived `Deserialize` for a
//! fieldless enum already refuses an unrecognized variant string, so a
//! malformed `intent`/`recovery_recommendation.strategy` fails the whole
//! parse rather than silently falling through to some default. That
//! parse failure is exactly what `validation::validate` turns into
//! "discarded entirely, never partially salvaged" (§21.7).
//!
//! `risk_level` reuses `policy::RiskLevel` rather than a second, parallel
//! enum: §21.6 calls it "informational context" using the same closed
//! taxonomy the Policy Engine already owns, and defining a duplicate
//! would let the two drift apart with no compiler check that they mean
//! the same thing.

use serde::{Deserialize, Serialize};

use crate::policy::RiskLevel;

/// The closed intent taxonomy. Covers `handlers/mod.rs`'s current command
/// set (`Navigation`, `FileRead`, `FileWrite`, `DirectoryCreate`) plus the
/// "must not be denied" corpus's known future
/// operations (`RecursiveDelete`, `PermissionChange`, `OwnershipChange`,
/// `PackageRemoval`) this schema needs to be ready for before those
/// handlers exist — same "shape now, data later" posture as
/// `policy::risk`'s `TOOLCHAIN_CRITICAL_PACKAGES`. `Other` is the
/// deliberate escape hatch for anything not yet named, rather than
/// forcing a parse failure for every future command.
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

/// §21.6's `recovery_recommendation.strategy` closed taxonomy.
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
    /// §21.6: "a claim the AI makes and the Rust core independently
    /// verifies; a mismatch is logged as an AI-divergence event" — see
    /// `ai::divergence`.
    pub escapes_sandbox: bool,
}

/// §21.6's full structured response, once parsed and enum-validated.
/// Still needs [`validation::validate`](crate::ai::validation::validate)'s
/// remaining checks (schema version, confidence clamping) before it's
/// trusted — a value of this type coming from `serde_json::from_str`
/// directly, bypassing `validate`, has skipped those.
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

/// What the Rust core sends the AI backend — the parsed command plus the
/// deterministic policy facts already computed (§21.1: "The Policy Engine
/// computes its own `policy_risk_level` and verdict before the AI is
/// invoked"). Deliberately **not** `policy::PolicyDecision` itself:
/// serializing that struct directly would couple the wire format to
/// `policy/`'s internal shape, and would need `Category`/`Verdict` to
/// grow `Serialize` impls this crate has no other use for. This is a
/// small, stable, purpose-built projection instead.
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
