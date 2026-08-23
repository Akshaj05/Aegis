//! "Malformed output discarded wholesale" (§21.7, §21.9's "Malformed AI
//! output... discarded entirely — never partially salvaged, never
//! field-by-field trusted").

use safeshell::ai::validation::{validate, AiValidationError};

fn well_formed() -> String {
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
fn empty_body_is_discarded() {
    assert!(matches!(validate(""), Err(AiValidationError::Parse(_))));
}

#[test]
fn html_error_page_is_discarded() {
    let result = validate("<html><body>502 Bad Gateway</body></html>");
    assert!(matches!(result, Err(AiValidationError::Parse(_))));
}

#[test]
fn valid_json_of_the_wrong_shape_entirely_is_discarded() {
    let result = validate(r#"{"error": "rate limited", "retry_after": 30}"#);
    assert!(matches!(result, Err(AiValidationError::Parse(_))));
}

#[test]
fn a_json_array_instead_of_an_object_is_discarded() {
    let result = validate(r#"["mkdir", "project"]"#);
    assert!(matches!(result, Err(AiValidationError::Parse(_))));
}

#[test]
fn one_missing_required_field_discards_the_entire_response() {
    // No partial salvage: every other field here is well-formed, but
    // `explanation` is missing entirely.
    let mut value: serde_json::Value = serde_json::from_str(&well_formed()).unwrap();
    value.as_object_mut().unwrap().remove("explanation");
    let result = validate(&value.to_string());
    assert!(matches!(result, Err(AiValidationError::Parse(_))));
}

#[test]
fn a_string_where_a_number_is_expected_discards_the_entire_response() {
    let json = well_formed().replace(
        "\"files_deleted_estimate\": 0",
        "\"files_deleted_estimate\": \"none\"",
    );
    assert!(matches!(validate(&json), Err(AiValidationError::Parse(_))));
}

#[test]
fn a_boolean_where_a_string_is_expected_discards_the_entire_response() {
    let json = well_formed().replace(
        "\"explanation\": \"Creates a new directory named project.\"",
        "\"explanation\": true",
    );
    assert!(matches!(validate(&json), Err(AiValidationError::Parse(_))));
}

#[test]
fn duplicate_json_keys_with_the_second_value_out_of_the_enum_still_discards() {
    // serde_json keeps the last value for a duplicate key; confirm the
    // *effective* value (the bogus one) is what gets validated, not
    // silently the first, valid one.
    let json = well_formed().replace(
        "\"risk_level\": \"low\"",
        "\"risk_level\": \"low\", \"risk_level\": \"catastrophic\"",
    );
    assert!(matches!(validate(&json), Err(AiValidationError::Parse(_))));
}

#[test]
fn an_unrecognized_recovery_strategy_discards_the_entire_response() {
    let json = well_formed().replace("no_recovery_needed", "self_destruct_the_sandbox");
    assert!(matches!(validate(&json), Err(AiValidationError::Parse(_))));
}

#[test]
fn a_well_formed_response_is_the_control_case_and_actually_validates() {
    // Proves the malformed cases above are failing for the right reason
    // (their specific defect), not because `well_formed()` itself is
    // broken.
    assert!(validate(&well_formed()).is_ok());
}
