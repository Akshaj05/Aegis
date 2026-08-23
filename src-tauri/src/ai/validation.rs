//! §21.7's deterministic validation of AI output: "parse or schema
//! failure means the output is discarded entirely, not partially
//! salvaged." [`validate`] is the single entry point every `AiBackend`
//! response must go through before anything downstream (persistence,
//! divergence detection, display) ever sees an [`AiPlan`] — there is no
//! other way to obtain a validated one from raw text in this crate.

use crate::ai::schema::AiPlan;

/// The only schema version this build understands. §21.7 doesn't say
/// what to do with a *future* schema version, but accepting one this
/// code was never validated against would mean trusting fields whose
/// meaning might have changed — treated the same as any other validation
/// failure: discarded, `ai_skipped` set, deterministic policy governs.
const SUPPORTED_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, thiserror::Error)]
pub enum AiValidationError {
    #[error("could not parse AI response as JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error(
        "unsupported schema_version {got:?} (this build understands {SUPPORTED_SCHEMA_VERSION:?})"
    )]
    UnsupportedSchemaVersion { got: String },
}

/// Parses and validates raw AI response text end to end. Confidence is
/// clamped into `[0.0, 1.0]` per §21.7 ("numeric fields are
/// range-clamped") rather than rejected outright — an out-of-range
/// confidence is a quality defect in the response, not evidence the rest
/// of the structured content is untrustworthy the way a schema mismatch
/// would be.
pub fn validate(raw: &str) -> Result<AiPlan, AiValidationError> {
    let mut plan: AiPlan = serde_json::from_str(raw)?;

    if plan.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(AiValidationError::UnsupportedSchemaVersion {
            got: plan.schema_version,
        });
    }

    plan.confidence = plan.confidence.clamp(0.0, 1.0);

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::schema::{Intent, RecoveryStrategy};
    use crate::policy::RiskLevel;

    fn valid_json() -> String {
        r#"{
            "schema_version": "1.0",
            "command": "mkdir project",
            "intent": "directory_create",
            "risk_level": "low",
            "affected_resources": ["project"],
            "predicted_effects": {
                "files_deleted_estimate": 0,
                "directories_deleted_estimate": 0,
                "escapes_sandbox": false
            },
            "preconditions": [],
            "reversible_within_safeshell": true,
            "recovery_recommendation": {
                "strategy": "no_recovery_needed",
                "description": "Nothing to recover."
            },
            "external_side_effects": false,
            "confidence": 0.95,
            "explanation": "Creates a new directory named project."
        }"#
        .to_string()
    }

    #[test]
    fn a_well_formed_response_validates() {
        let plan = validate(&valid_json()).unwrap();
        assert_eq!(plan.intent, Intent::DirectoryCreate);
        assert_eq!(plan.risk_level, RiskLevel::Low);
        assert_eq!(
            plan.recovery_recommendation.strategy,
            RecoveryStrategy::NoRecoveryNeeded
        );
    }

    #[test]
    fn malformed_json_is_discarded_entirely() {
        let result = validate("not json at all");
        assert!(matches!(result, Err(AiValidationError::Parse(_))));
    }

    #[test]
    fn truncated_json_is_discarded_entirely() {
        let truncated = &valid_json()[..40];
        let result = validate(truncated);
        assert!(matches!(result, Err(AiValidationError::Parse(_))));
    }

    #[test]
    fn a_field_with_the_wrong_type_is_discarded_entirely() {
        let json = valid_json().replace("\"confidence\": 0.95", "\"confidence\": \"high\"");
        let result = validate(&json);
        assert!(matches!(result, Err(AiValidationError::Parse(_))));
    }

    #[test]
    fn an_unsupported_schema_version_is_rejected_even_though_it_parses_cleanly() {
        let json = valid_json().replace("\"1.0\"", "\"2.0\"");
        let result = validate(&json);
        assert!(matches!(
            result,
            Err(AiValidationError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn confidence_above_one_is_clamped_not_rejected() {
        let json = valid_json().replace("\"confidence\": 0.95", "\"confidence\": 5.0");
        let plan = validate(&json).unwrap();
        assert_eq!(plan.confidence, 1.0);
    }

    #[test]
    fn negative_confidence_is_clamped_not_rejected() {
        let json = valid_json().replace("\"confidence\": 0.95", "\"confidence\": -3.0");
        let plan = validate(&json).unwrap();
        assert_eq!(plan.confidence, 0.0);
    }

    #[test]
    fn an_unrecognized_enum_value_anywhere_in_the_payload_is_discarded_entirely() {
        let json = valid_json().replace("directory_create", "reformat_the_universe");
        let result = validate(&json);
        assert!(matches!(result, Err(AiValidationError::Parse(_))));
    }
}
