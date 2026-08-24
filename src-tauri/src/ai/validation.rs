// Validates raw AI response text into a trusted AiPlan: JSON parsing,
// enum-casing normalization, schema-version check, and confidence
// clamping. Malformed or unsupported responses are discarded entirely.

use crate::ai::schema::AiPlan;

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

fn lowercase_known_enum_fields(value: &mut serde_json::Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    for key in ["risk_level", "intent"] {
        if let Some(serde_json::Value::String(s)) = obj.get_mut(key) {
            *s = s.to_lowercase();
        }
    }
    if let Some(serde_json::Value::Object(recovery)) = obj.get_mut("recovery_recommendation") {
        if let Some(serde_json::Value::String(s)) = recovery.get_mut("strategy") {
            *s = s.to_lowercase();
        }
    }
}

pub fn validate(raw: &str) -> Result<AiPlan, AiValidationError> {
    let mut value: serde_json::Value = serde_json::from_str(raw)?;
    lowercase_known_enum_fields(&mut value);
    let mut plan: AiPlan = serde_json::from_value(value)?;

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

    #[test]
    fn a_capitalized_risk_level_from_a_local_model_is_normalized_not_discarded() {
        let json = valid_json().replace("\"risk_level\": \"low\"", "\"risk_level\": \"Low\"");
        let plan = validate(&json).unwrap();
        assert_eq!(plan.risk_level, RiskLevel::Low);
    }

    #[test]
    fn a_capitalized_intent_and_recovery_strategy_are_normalized_not_discarded() {
        let json = valid_json()
            .replace(
                "\"intent\": \"directory_create\"",
                "\"intent\": \"Directory_Create\"",
            )
            .replace(
                "\"strategy\": \"no_recovery_needed\"",
                "\"strategy\": \"NO_RECOVERY_NEEDED\"",
            );
        let plan = validate(&json).unwrap();
        assert_eq!(plan.intent, Intent::DirectoryCreate);
        assert_eq!(
            plan.recovery_recommendation.strategy,
            RecoveryStrategy::NoRecoveryNeeded
        );
    }

    #[test]
    fn a_genuinely_unrecognized_risk_level_still_fails_even_after_lowercasing() {
        let json = valid_json().replace("\"risk_level\": \"low\"", "\"risk_level\": \"Extreme\"");
        let result = validate(&json);
        assert!(matches!(result, Err(AiValidationError::Parse(_))));
    }
}
